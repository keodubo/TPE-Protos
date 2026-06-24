#include <netdb.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "resolv.h"
#include "socks5.h"

struct resolv_args {
    fd_selector    selector;
    int            client_fd;
    struct socks5 *socks;
    char           name[REQUEST_FQDN_MAX + 1];
    char           service[6];
    selector_block_job *job;
};

/*
 * Contador de resoluciones DNS en vuelo (hilos detached dentro de getaddrinfo).
 *
 * Vive junto al modulo de resolucion para que el bucle principal pueda DRENAR
 * los hilos pendientes antes de destruir el selector y el pool de conexiones
 * (ver main.c, etiqueta finally). Sin este drenaje habria un UAF: un hilo DNS
 * que retorna de getaddrinfo llama selector_notify_block() sobre un selector
 * ya liberado, y al hacer su socks5_unref() final re-encolaria el objeto en un
 * pool ya destruido -> leak. El contador se incrementa al despachar el hilo y
 * se decrementa recien cuando el hilo termino TODO su trabajo (incluido el
 * notify_block), de modo que count==0 garantiza que ningun hilo sigue tocando ni
 * el selector ni el objeto socks5.
 *
 * D9 (purista): el contador lo tocan SOLO funciones del hilo principal:
 * resolv_pending_inc() en resolv_dispatch, resolv_pending_dec() en resolv_cleanup
 * (que corre como cleanup del job, en el hilo del selector) y resolv_pending_count()
 * en el drenaje de main.c. El hilo de getaddrinfo NO lo toca, asi que es un
 * unsigned plano, sin mutex.
 */
static unsigned        resolv_pending = 0;

static void
resolv_pending_inc(void) {
    resolv_pending++;
}

static void
resolv_pending_dec(void) {
    if (resolv_pending > 0) {
        resolv_pending--;
    }
}

/* Cantidad de hilos DNS aun en vuelo. Lo consume main.c al apagar. */
unsigned
resolv_pending_count(void) {
    return resolv_pending;
}

static void
resolv_cleanup(struct selector_key *key) {
    socks5_unref((struct socks5 *) key->data);
    resolv_pending_dec();
}

static void *
resolv_blocking(void *data) {
    struct resolv_args *args = data;
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    errno = 0;
    const int ret = getaddrinfo(args->name, args->service, &hints, &res);
    args->socks->resolv.gai_error = ret;
    args->socks->resolv.sys_errno = ret == EAI_SYSTEM ? errno : 0;
    if (ret == 0) {
        args->socks->origin_resolution = res;
        args->socks->current_resolution = res;
    }

    /*
     * D9 (purista): este hilo NO toca estado compartido (ni references, ni el
     * pool, ni el contador resolv_pending). Solo escribio el resultado arriba y
     * ahora notifica al hilo principal. TODO el lifetime (unref + pending_dec)
     * viaja como cleanup del job y corre en el hilo principal (resolv_cleanup),
     * incluso si el fd fue cerrado/reutilizado.
     *
     * Identidad por objeto (f15): selector_notify_block_reserved despacha el block
     * SOLO si el fd sigue mapeado al MISMO struct socks5 (args->socks). Si el
     * cliente se desconecto y el fd se reasigno, el handle_block no se dispara,
     * pero el cleanup del job igual corre y libera la referencia.
     *
     * Contrato de drenaje (f14, D9.3): main.c no destruye el selector mientras
     * resolv_pending_count() > 0, y este hilo esta contado. Como client_fd se
     * capturo valido en el dispatch y fd_size solo crece, notify_block_reserved
     * NO puede fallar mientras el selector exista -> el fallo es INALCANZABLE.
     * Lo afirmamos con assert para documentar el invariante, sin que el hilo DNS
     * toque pool/refcount.
     */
    const selector_status st = selector_notify_block_reserved(args->selector,
                                                              args->client_fd,
                                                              args->socks,
                                                              resolv_cleanup,
                                                              args->job);
    assert(st == SELECTOR_SUCCESS);
    (void) st;
    free(args);
    return NULL;
}

int
resolv_dispatch(struct selector_key *key, const char *name, const uint16_t port) {
    struct resolv_args *args = malloc(sizeof(*args));
    if (args == NULL) {
        return -1;
    }
    memset(args, 0, sizeof(*args));
    args->job = selector_block_job_new();
    if (args->job == NULL) {
        free(args);
        return -1;
    }

    struct socks5 *s = key->data;
    args->selector  = key->s;
    args->client_fd = s->client_fd;
    args->socks     = s;
    snprintf(args->name, sizeof(args->name), "%s", name);
    snprintf(args->service, sizeof(args->service), "%u", (unsigned)ntohs(port));

    pthread_t tid;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        selector_block_job_free(args->job);
        free(args);
        return -1;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        pthread_attr_destroy(&attr);
        selector_block_job_free(args->job);
        free(args);
        return -1;
    }

    socks5_ref(s);
    resolv_pending_inc();
    if (pthread_create(&tid, &attr, resolv_blocking, args) != 0) {
        resolv_pending_dec();
        pthread_attr_destroy(&attr);
        socks5_unref(s);
        selector_block_job_free(args->job);
        free(args);
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}
