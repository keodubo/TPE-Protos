/**
 * main.c — Servidor del TPE: proxy SOCKS5 (Protos, ITBA).
 *
 * Interpreta los argumentos, monta el socket pasivo y corre el bucle de
 * eventos del `selector`. Cada conexión entrante se maneja con una máquina
 * de estados no bloqueante (src/server/socks5nio.c).
 *
 *   M0: esqueleto echo (reemplazado).
 *   M1: negociación de método SOCKS5 (HELLO).  <-- estado actual
 *   M2+: auth, request, connect, relay...
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

#define LISTEN_BACKLOG 20

static volatile sig_atomic_t done = false;

static void
sigterm_handler(const int signal) {
    (void) signal;
    done = true;   // async-signal-safe: sólo seteamos la bandera, no logueamos
}

/** crea, bindea y pone a escuchar un socket pasivo TCP IPv4 no bloqueante */
static int
setup_passive_socket(const char *addr, unsigned short port, const char **err) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);   // "0.0.0.0" / TODO M5: IPv6
    }

    const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { *err = "no se pudo crear el socket"; return -1; }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
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
        perror(err_msg);
        ret = 1;
    } else {
        ret = 0;
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
