/**
 * main.c — Servidor del TPE: proxy SOCKS5 (Protos, ITBA).
 *
 * Interpreta los argumentos, monta el socket pasivo y corre el bucle de
 * eventos del `selector`. Cada conexión entrante se maneja con una máquina
 * de estados no bloqueante (src/server/socks5nio.c).
 *
 * Estado actual: M5.
 *   M1: negociación de método SOCKS5 (HELLO).
 *   M2: autenticación usuario/contraseña (RFC1929).
 *   M3: REQUEST + CONNECT.
 *   M4: relay/COPY bidireccional (parciales + half-close).
 *   M5: DNS no bloqueante + IPv6 + FQDN + retry multi-IP.
 *
 * Nota de apagado (M5): el bucle de eventos drena los hilos de resolución DNS
 * en vuelo (`resolv_pending_count`) antes de destruir el selector y el pool de
 * conexiones, para evitar que un hilo que retorna de getaddrinfo toque memoria
 * ya liberada (ver bloque `finally`).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "args.h"
#include "selector.h"
#include "socks5nio.h"
#include "users.h"

/*
 * Definido en resolv.c. Cantidad de hilos de resolución DNS aún en vuelo.
 * Se declara aquí (en vez de en un header) porque main.c es el único consumidor
 * y resolv.h sólo expone el dispatch; el contador es detalle de apagado.
 */
unsigned resolv_pending_count(void);

#define LISTEN_BACKLOG 20

static volatile sig_atomic_t done = false;

static void
sigterm_handler(const int signal) {
    (void) signal;
    done = true;   // async-signal-safe: sólo seteamos la bandera, no logueamos
}

/**
 * crea, bindea y pone a escuchar un socket pasivo TCP no bloqueante.
 *
 * Acepta literales IPv4 (AF_INET) o IPv6 (AF_INET6) en `addr`. Si el string no
 * parsea como ninguna de las dos familias se reporta error en *err en vez de
 * caer silenciosamente a INADDR_ANY (un fallback mudo haría que el operador
 * creyera escuchar en la dirección pedida mientras escucha en todas las
 * interfaces). La cadena vacía o "0.0.0.0" siguen valiendo como "todas las
 * interfaces IPv4".
 */
static int
setup_passive_socket(const char *addr, unsigned short port, const char **err) {
    struct sockaddr_storage ss;
    socklen_t               sa_len = 0;
    int                     family = AF_INET;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in  *sa4 = (struct sockaddr_in  *) &ss;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &ss;

    if (addr == NULL || addr[0] == '\0') {
        // sin -l: escuchar en todas las interfaces IPv4
        family            = AF_INET;
        sa4->sin_family   = AF_INET;
        sa4->sin_port     = htons(port);
        sa4->sin_addr.s_addr = htonl(INADDR_ANY);
        sa_len            = sizeof(*sa4);
    } else if (inet_pton(AF_INET, addr, &sa4->sin_addr) == 1) {
        family            = AF_INET;
        sa4->sin_family   = AF_INET;
        sa4->sin_port     = htons(port);
        sa_len            = sizeof(*sa4);
    } else if (inet_pton(AF_INET6, addr, &sa6->sin6_addr) == 1) {
        family            = AF_INET6;
        sa6->sin6_family  = AF_INET6;
        sa6->sin6_port    = htons(port);
        sa_len            = sizeof(*sa6);
    } else {
        // no es IPv4 ni IPv6 literal: no caer mudo a INADDR_ANY (f6)
        *err  = "la dirección de -l no es un literal IPv4 ni IPv6 válido";
        errno = 0;   // fallo de config, no de syscall: main no anexa strerror
        return -1;
    }

    const int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { *err = "no se pudo crear el socket"; return -1; }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fd, (struct sockaddr *) &ss, sa_len) < 0) {
        *err = "no se pudo hacer bind"; close(fd); return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) < 0) {
        *err = "no se pudo hacer listen"; close(fd); return -1;
    }
    if (selector_fd_set_nio(fd) == -1) {
        *err = "no se pudo poner el socket en modo no bloqueante";
        close(fd); return -1;
    }
    return fd;
}

int
main(const int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);

    // cargar la tabla de usuarios del proxy (RFC1929) desde los -u name:pass
    for (int i = 0; i < MAX_USERS && args.users[i].name != NULL; i++) {
        if (!users_add(args.users[i].name, args.users[i].pass)) {
            fprintf(stderr,
                    "aviso: usuario '-u %s' ignorado (vacío, duplicado o inválido)\n",
                    args.users[i].name);
        }
    }

    close(STDIN_FILENO);            // no leemos de stdin
    signal(SIGPIPE, SIG_IGN);       // no morir al escribir sobre un socket roto
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const char     *err_msg  = NULL;
    selector_status ss       = SELECTOR_SUCCESS;
    fd_selector     selector = NULL;
    int             socks_fd = -1;

    socks_fd = setup_passive_socket(args.socks_addr, args.socks_port, &err_msg);
    if (socks_fd < 0) {
        goto finally;
    }
    fprintf(stdout, "[socks5] proxy escuchando en %s:%u\n",
            args.socks_addr, args.socks_port);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != 0) {
        err_msg = "no se pudo inicializar el selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "no se pudo crear el selector";
        goto finally;
    }

    const struct fd_handler passive = {
        .handle_read  = socksv5_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
        .handle_block = NULL,
    };
    ss = selector_register(selector, socks_fd, &passive, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "no se pudo registrar el socket pasivo";
        goto finally;
    }

    while (!done) {
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "error en el bucle de eventos";
            goto finally;
        }
    }
    fprintf(stdout, "señal recibida, cerrando...\n");   // log fuera del handler

    int ret = 0;
finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", err_msg ? err_msg : "",
                ss == SELECTOR_IO ? strerror(errno) : selector_error(ss));
        ret = 2;
    } else if (err_msg != NULL) {
        // errno==0 => fallo de configuración (p.ej. -l no parseable, f6), no de
        // syscall: evitamos que perror anexe un "Success" engañoso.
        if (errno != 0) {
            perror(err_msg);
        } else {
            fprintf(stderr, "%s\n", err_msg);
        }
        ret = 1;
    } else {
        ret = 0;
    }

    /*
     * Drenaje de hilos DNS en vuelo (f14). Un hilo de resolución detached que
     * sigue dentro de getaddrinfo todavía notificará al selector al terminar; si
     * liberáramos el selector o el pool antes, tocaría memoria ya liberada. El
     * cleanup del job de notificación hace el unref y baja el contador en el hilo
     * principal. Esperamos a que resolv_pending_count() llegue a 0 antes de
     * destruir nada. Precondición consumida por resolv.c.
     */
    if (selector != NULL) {
        while (resolv_pending_count() > 0) {
            const selector_status drain_status = selector_select(selector);
            if (drain_status != SELECTOR_SUCCESS) {
                fprintf(stderr, "aviso: error drenando DNS pendiente: %s\n",
                        drain_status == SELECTOR_IO ? strerror(errno)
                                                    : selector_error(drain_status));
            }
        }
    }

    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    socksv5_pool_destroy();
    if (socks_fd >= 0) {
        close(socks_fd);
    }
    return ret;
}
