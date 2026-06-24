#include <netdb.h>
#include <pthread.h>
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
 * notify_block y el unref), de modo que count==0 garantiza que ningun hilo
 * sigue tocando ni el selector ni el objeto socks5.
 */
static pthread_mutex_t resolv_pending_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned        resolv_pending       = 0;

static void
resolv_pending_inc(void) {
    pthread_mutex_lock(&resolv_pending_mutex);
    resolv_pending++;
    pthread_mutex_unlock(&resolv_pending_mutex);
}

static void
resolv_pending_dec(void) {
    pthread_mutex_lock(&resolv_pending_mutex);
    if (resolv_pending > 0) {
        resolv_pending--;
    }
    pthread_mutex_unlock(&resolv_pending_mutex);
}

/* Cantidad de hilos DNS aun en vuelo. Lo consume main.c al apagar. */
unsigned
resolv_pending_count(void) {
    pthread_mutex_lock(&resolv_pending_mutex);
    const unsigned n = resolv_pending;
    pthread_mutex_unlock(&resolv_pending_mutex);
    return n;
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
     * Precondicion (f14): el selector NO debe ser destruido mientras este hilo
     * siga vivo. El bucle principal lo garantiza drenando resolv_pending_count()
     * hasta 0 antes de selector_destroy()/socksv5_pool_destroy() (ver main.c).
     * El unref y el decremento de pending viajan como cleanup del job y corren
     * en el hilo principal, incluso si el fd fue cerrado/reutilizado.
     *
     * Suposicion notify-por-fd (f15): selector_notify_block() despacha el block
     * por numero de fd, no por objeto. Si el cliente se desconectara durante
     * getaddrinfo, su fd podria reasignarse a otra conexion antes de procesar
     * el job; handle_block_notifications() guarda con ITEM_USED (no crashea),
     * pero el refcount mantiene vivo el objeto correcto. Ventana estrecha
     * (requiere reuso exacto del fd en el mismo ciclo de select) se mitiga con
     * selector_notify_block_with_data(): el selector sólo despacha si el item
     * actual del fd sigue apuntando al mismo struct socks5.
     */
    const selector_status st = selector_notify_block_reserved(args->selector,
                                                              args->client_fd,
                                                              args->socks,
                                                              resolv_cleanup,
                                                              args->job);
    if (st != SELECTOR_SUCCESS) {
        /*
         * Fallback raro (selector destruido/corrupto pese al contrato de drenaje):
         * no podemos dejar pending colgado. Soltamos la ref acá; socks5_unref
         * protege el pool con mutex.
         */
        selector_block_job_free(args->job);
        socks5_unref(args->socks);
        resolv_pending_dec();
    }
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
