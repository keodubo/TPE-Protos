/**
 * main.c — Servidor del TPE: proxy SOCKS5 (Protos, ITBA).
 *
 * ============================  MILESTONE M0  ============================
 * Esqueleto NO BLOQUEANTE con servicio de ECHO. Su único objetivo es
 * demostrar que el toolkit de la cátedra está correctamente integrado:
 *
 *   - socket pasivo en modo no bloqueante,
 *   - multiplexado de muchos clientes en UN solo hilo vía `selector`,
 *   - lecturas/escrituras PARCIALES manejadas con `buffer`,
 *   - manejo de señales para graceful shutdown (SIGTERM/SIGINT),
 *   - parsing de argumentos POSIX (args.c provisto por la cátedra).
 *
 * A medida que avancen los milestones, el handler de echo se reemplaza por
 * la máquina de estados de SOCKS5:
 *   M1  HELLO (RFC1928, negociación de método)      -> src/server/hello.c
 *   M2  AUTH user/pass (RFC1929)                     -> src/server/auth.c
 *   M3  REQUEST + CONNECT IPv4                        -> src/server/request.c
 *   M4  RELAY bidireccional (COPY)                    -> src/server/copy.c
 *   M5  DNS no bloqueante (pthread + notify_block)    -> src/server/resolv.c
 *   ... ver docs/DECISIONS.md y la guía de arranque.
 * =======================================================================
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
#include <netinet/tcp.h>

#include "args.h"
#include "selector.h"
#include "buffer.h"

/** tamaño del buffer de echo por conexión (configurable en runtime en M7) */
#define ECHO_BUFFER_SIZE 2048
/** backlog del listen(2) */
#define LISTEN_BACKLOG   20

/** flag de apagado, lo setea el handler de señales */
static bool done = false;

static void
sigterm_handler(const int signal) {
    fprintf(stdout, "señal %d recibida, cerrando...\n", signal);
    done = true;
}

/* ===================================================================== */
/* M0: estado por conexión de echo.                                      */
/* (en M1 se reemplaza por `struct socks5` con su máquina de estados)    */
/* ===================================================================== */
struct echo_conn {
    buffer  buf;
    uint8_t raw[ECHO_BUFFER_SIZE];
};

static void echo_read (struct selector_key *key);
static void echo_write(struct selector_key *key);
static void echo_close(struct selector_key *key);

static const struct fd_handler echo_handler = {
    .handle_read  = echo_read,
    .handle_write = echo_write,
    .handle_close = echo_close,
    .handle_block = NULL,
};

/** acepta una nueva conexión entrante y la registra en el selector */
static void
passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len = sizeof(client_addr);

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        return; /* EAGAIN u otro: simplemente no hay nada que aceptar ahora */
    }
    if (selector_fd_set_nio(client) == -1) {
        close(client);
        return;
    }

    struct echo_conn *e = malloc(sizeof(*e));
    if (e == NULL) {
        close(client);
        return;
    }
    buffer_init(&e->buf, sizeof(e->raw), e->raw);

    if (selector_register(key->s, client, &echo_handler, OP_READ, e)
            != SELECTOR_SUCCESS) {
        free(e);
        close(client);
        return;
    }
}

/** hay datos para leer del cliente: los guardamos en el buffer */
static void
echo_read(struct selector_key *key) {
    struct echo_conn *e = key->data;
    size_t   count;
    uint8_t *ptr = buffer_write_ptr(&e->buf, &count);

    if (count == 0) {
        /* buffer lleno: dejamos de leer y priorizamos vaciarlo escribiendo */
        selector_set_interest_key(key, OP_WRITE);
        return;
    }

    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(&e->buf, n);
        /* nos interesa seguir leyendo Y devolver lo leído */
        selector_set_interest_key(key, OP_READ | OP_WRITE);
    } else if (n == 0) {
        /* el cliente cerró: lo desregistramos (dispara echo_close) */
        selector_unregister_fd(key->s, key->fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/** el socket está listo para escribir: drenamos el buffer (echo) */
static void
echo_write(struct selector_key *key) {
    struct echo_conn *e = key->data;
    size_t   count;
    uint8_t *ptr = buffer_read_ptr(&e->buf, &count);

    if (count == 0) {
        /* nada pendiente para escribir: volvemos a solo lectura */
        selector_set_interest_key(key, OP_READ);
        return;
    }

    const ssize_t n = send(key->fd, ptr, count, 0);
    if (n >= 0) {
        buffer_read_adv(&e->buf, n);
        if (!buffer_can_read(&e->buf)) {
            selector_set_interest_key(key, OP_READ);
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        selector_unregister_fd(key->s, key->fd);
    }
}

/** se desregistró el fd: liberamos recursos y cerramos */
static void
echo_close(struct selector_key *key) {
    struct echo_conn *e = key->data;
    if (e != NULL) {
        free(e);
    }
    close(key->fd);
}

/* ===================================================================== */

/** crea, bindea y pone a escuchar un socket pasivo TCP IPv4 no bloqueante */
static int
setup_passive_socket(const char *addr, unsigned short port, const char **err) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    /* "0.0.0.0" -> INADDR_ANY ; TODO M5: soportar IPv6 vía getaddrinfo */
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { *err = "no se pudo crear el socket"; return -1; }

    /* permite reusar la dirección al reiniciar (evita "Address already in use") */
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

    /* no leemos de stdin */
    close(STDIN_FILENO);

    /* SIGPIPE: si un peer cierra mientras escribimos, NO queremos morir */
    signal(SIGPIPE, SIG_IGN);
    /* graceful shutdown (M8 lo refina: esperar conexiones en curso) */
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
    fprintf(stdout, "[M0-echo] escuchando SOCKS en %s:%u\n",
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
        .handle_read  = passive_accept,
        .handle_write = NULL,
        .handle_close = NULL,
        .handle_block = NULL,
    };
    ss = selector_register(selector, socks_fd, &passive, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "no se pudo registrar el socket pasivo";
        goto finally;
    }

    /* bucle principal: una iteración por evento o por timeout */
    while (!done) {
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "error en el bucle de eventos";
            goto finally;
        }
    }

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
    if (socks_fd >= 0) {
        close(socks_fd);
    }
    return ret;
}
