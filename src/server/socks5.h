#ifndef SOCKS5_H_TPE_SOCKS5
#define SOCKS5_H_TPE_SOCKS5

#include <stdbool.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/socket.h>

#include "auth.h"
#include "buffer.h"
#include "copy.h"
#include "hello.h"
#include "request.h"
#include "socks5nio.h"
#include "stm.h"

/*
 * Helpers compartidos por las TU que tocan una conexión SOCKS5
 * (socks5nio.c, copy.c). Centralizados acá para evitar divergencia (f26).
 */

/** recupera el struct socks5 colgado del selector_key */
#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

/*
 * macOS no define MSG_NOSIGNAL; el fallback a 0 lo hace portable. La defensa
 * real anti-SIGPIPE es signal(SIGPIPE, SIG_IGN) global (main.c). Definido acá
 * para que todos los send() del proyecto usen el mismo flag de forma uniforme.
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum socks_v5state {
    HELLO_READ  = 0,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
};

struct hello_st {
    buffer              *rb, *wb;
    struct hello_parser  parser;
    uint8_t              method;
    uint8_t              offered[8];
    uint8_t              noffered;
};

struct auth_st {
    buffer              *rb, *wb;
    struct auth_parser   parser;
    uint8_t              status;
};

struct request_st {
    buffer                *rb, *wb;
    struct request_parser  parser;
    uint8_t                rep;
    bool                   initialized;
};

/*
 * f42: connecting_st guarda un único uint8_t (el REP del intento de connect en
 * curso). Se mantiene como struct para dejar lugar a más estado por-intento
 * (timeouts, contador de IPs probadas) sin tocar la firma de struct socks5.
 */
struct connecting_st {
    uint8_t                rep;
};

struct resolv_st {
    bool                   started;
    int                    gai_error;
    int                    sys_errno;
};

/*
 * f42: costo por conexión del pool. struct socks5 embebe dos struct copy
 * completos (copy_client/copy_origin, cada uno con su selector_key) más dos
 * buffers crudos de IO_BUFFER_SIZE (default 8192) -> ~16 KiB de buffers por
 * conexión. Con el objetivo de >=500 conexiones esto domina la huella de RAM
 * (~8 MiB sólo en buffers). El union client (hello/auth/request) reusa una sola
 * región porque los tres estados nunca coexisten; los dos copy NO se solapan con
 * el union porque COPY usa ambos buffers en simultáneo.
 */
struct socks5 {
    int                     client_fd;
    int                     origin_fd;

    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    unsigned                id;
    char                    username[AUTH_MAX_FIELD + 1];
    char                    dest_host[REQUEST_FQDN_MAX + 1];
    unsigned                dest_port;
    bool                    access_logged;

    struct state_machine    stm;

    union {
        struct hello_st      hello;
        struct auth_st       auth;
        struct request_st    request;
    } client;

    struct connecting_st    connecting;
    struct resolv_st        resolv;
    struct copy             copy_client;
    struct copy             copy_origin;

    struct addrinfo        *origin_resolution;
    struct addrinfo        *current_resolution;

    uint8_t                *raw_buff_a;
    uint8_t                *raw_buff_b;
    size_t                  raw_buff_size;
    buffer                  read_buffer;
    buffer                  write_buffer;

    /*
     * D9 (purista): el refcount lo toca SOLO el hilo principal. La referencia del
     * DNS se toma en resolv_dispatch y se libera en el cleanup del job (ambos en
     * el hilo principal); el hilo de getaddrinfo nunca toca references ni el pool.
     * Por eso es un unsigned plano, sin _Atomic ni mutex.
     */
    unsigned                references;
    struct socks5          *next;
};

void socks5_ref(struct socks5 *s);
void socks5_unref(struct socks5 *s);

#endif
