/**
 * socks5nio.c — máquina de estados de una conexión SOCKS5 (no bloqueante).
 *
 * M1: negociación de método (HELLO, RFC1928 §3).
 * M2: autenticación usuario/contraseña (AUTH, RFC1929).
 * Los handlers top-level (socksv5_read/write) delegan en la `stm`; cuando la
 * máquina llega a DONE o ERROR se desregistran y cierran los fds.
 *
 * M3: REQUEST + CONNECT (genérico sobre struct sockaddr).
 * M4: relay bidireccional transparente cliente <-> origin (half-close real).
 * M5: resolución DNS no bloqueante (hilo getaddrinfo + selector_notify_block),
 *     soporte IPv6 y FQDN, y retry multi-IP (request_connect_next) probando las
 *     direcciones devueltas hasta conectar o agotarlas.
 */
#include <stdlib.h>   // malloc
#include <string.h>   // memset
#include <stdint.h>   // uint8_t (buffer.h lo usa pero no lo incluye)
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>    // fcntl, FD_CLOEXEC
#include <unistd.h>   // close
#include <sys/socket.h>
#include <arpa/inet.h>

#include "selector.h"
#include "stm.h"
#include "buffer.h"
#include "netutils.h"
#include "hello.h"
#include "auth.h"
#include "request.h"
#include "connect.h"
#include "copy.h"
#include "resolv.h"
#include "users.h"
#include "dbg.h"
#include "metrics.h"
#include "logger.h"
#include "socks5.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

// ATTACHMENT y el fallback de MSG_NOSIGNAL viven en socks5.h (compartidos con
// copy.c) para evitar divergencia entre TU (f26).

////////////////////////////////////////////////////////////////////////////////
// Pool de objetos (reusar alocaciones para sostener muchas conexiones)
static struct socks5  *pool      = NULL;
static unsigned        pool_size = 0;
static const unsigned  max_pool  = 50;
static size_t          io_buffer_size = IO_BUFFER_SIZE;

/** contador de conexiones (para identificarlas en los logs) */
static unsigned        conn_counter = 0;

/*
 * Prototipos de los handlers de estado (las definiciones están más abajo). Se
 * declaran acá para poder definir client_statbl ANTES de socks5_new y asignarlo
 * directo (ret->stm.states = client_statbl), sin la indirección de un wrapper
 * (f18). No se puede forward-declarar el array como 'static const T arr[];'
 * porque gcc lo rechaza (array size missing); por eso se adelanta la tabla.
 */
static void     hello_read_init     (const unsigned state, struct selector_key *key);
static unsigned hello_read          (struct selector_key *key);
static unsigned hello_write         (struct selector_key *key);
static unsigned auth_read           (struct selector_key *key);
static unsigned auth_write          (struct selector_key *key);
static void     request_read_init   (const unsigned state, struct selector_key *key);
static unsigned request_read        (struct selector_key *key);
static void     request_resolv_init (const unsigned state, struct selector_key *key);
static unsigned request_resolv_done (struct selector_key *key);
static unsigned request_connecting_read(struct selector_key *key);
static unsigned request_connecting  (struct selector_key *key);
static unsigned request_write       (struct selector_key *key);

/** tabla de estados (índices correlativos con enum socks_v5state) */
static const struct state_definition client_statbl[] = {
    {
        .state         = HELLO_READ,
        .on_arrival    = hello_read_init,
        .on_read_ready = hello_read,
    }, {
        .state          = HELLO_WRITE,
        .on_write_ready = hello_write,
    }, {
        .state         = AUTH_READ,
        .on_read_ready = auth_read,
    }, {
        .state          = AUTH_WRITE,
        .on_write_ready = auth_write,
    }, {
        .state         = REQUEST_READ,
        .on_arrival    = request_read_init,
        .on_read_ready = request_read,
    }, {
        .state          = REQUEST_RESOLV,
        .on_arrival     = request_resolv_init,
        .on_block_ready = request_resolv_done,
    }, {
        .state          = REQUEST_CONNECTING,
        .on_read_ready  = request_connecting_read,
        .on_write_ready = request_connecting,
    }, {
        .state          = REQUEST_WRITE,
        .on_write_ready = request_write,
    }, {
        .state          = COPY,
        .on_arrival     = copy_init,
        .on_read_ready  = copy_read,
        .on_write_ready = copy_write,
    }, {
        .state = DONE,
    }, {
        .state = ERROR,
    },
};

/** entrada a la autenticación desde HELLO_WRITE (definida en la sección AUTH) */
static unsigned hello_to_auth(struct selector_key *key);
static unsigned auth_to_request(struct selector_key *key);

size_t
socksv5_buffer_size(void) {
    return io_buffer_size;
}

bool
socksv5_buffer_size_set(const size_t size) {
    if (size < IO_BUFFER_SIZE_MIN || size > IO_BUFFER_SIZE_MAX) {
        return false;
    }
    io_buffer_size = size;
    return true;
}

static void
socks5_buffers_free(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    free(s->raw_buff_a);
    free(s->raw_buff_b);
    s->raw_buff_a = NULL;
    s->raw_buff_b = NULL;
    s->raw_buff_size = 0;
}

static bool
socks5_buffers_resize(struct socks5 *s, const size_t size) {
    if (s->raw_buff_a != NULL && s->raw_buff_b != NULL
            && s->raw_buff_size == size) {
        return true;
    }

    uint8_t *a = malloc(size);
    uint8_t *b = malloc(size);
    if (a == NULL || b == NULL) {
        free(a);
        free(b);
        return false;
    }

    socks5_buffers_free(s);
    s->raw_buff_a = a;
    s->raw_buff_b = b;
    s->raw_buff_size = size;
    return true;
}

static struct socks5 *
socks5_new(const int client_fd) {
    struct socks5 *ret;
    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
        if (ret != NULL) {
            memset(ret, 0, sizeof(*ret));
        }
    } else {
        ret = pool;
        pool = pool->next;
        pool_size--;
        uint8_t *raw_a = ret->raw_buff_a;
        uint8_t *raw_b = ret->raw_buff_b;
        const size_t raw_size = ret->raw_buff_size;
        memset(ret, 0, sizeof(*ret));
        ret->raw_buff_a = raw_a;
        ret->raw_buff_b = raw_b;
        ret->raw_buff_size = raw_size;
    }
    if (ret == NULL) {
        return NULL;
    }
    if (!socks5_buffers_resize(ret, io_buffer_size)) {
        socks5_buffers_free(ret);
        free(ret);
        return NULL;
    }
    ret->client_fd  = client_fd;
    ret->origin_fd  = -1;
    ret->references = 1;

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = client_statbl;
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  ret->raw_buff_size, ret->raw_buff_a);
    buffer_init(&ret->write_buffer, ret->raw_buff_size, ret->raw_buff_b);
    return ret;
}

static void
socks5_resolution_clear(struct socks5 *s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = NULL;
        s->current_resolution = NULL;
    }
}

// D9 (purista): references y el pool (pool/pool_size) los toca SOLO el hilo
// principal. La referencia del DNS se toma en resolv_dispatch y se libera en el
// cleanup del job (resolv_cleanup), ambos en el hilo principal; el hilo de
// getaddrinfo nunca toca el refcount ni el pool. Por eso el inc/dec es ++/--
// plano y el reciclaje al pool no necesita mutex.
void
socks5_ref(struct socks5 *s) {
    if (s != NULL) {
        s->references++;
    }
}

void
socks5_unref(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    if (--s->references == 0) {
        socks5_resolution_clear(s);
        if (pool_size < max_pool) {
            s->next    = pool;
            pool       = s;
            pool_size++;
        } else {
            socks5_buffers_free(s);
            free(s);
        }
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s = pool;
    while (s != NULL) {
        next = s->next;
        socks5_resolution_clear(s);
        socks5_buffers_free(s);
        free(s);
        s = next;
    }
    pool      = NULL;
    pool_size = 0;
}

////////////////////////////////////////////////////////////////////////////////
// Handlers de selección de una conexión establecida
static void socksv5_read (struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read  = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

static const struct fd_handler socks5_origin_handler = {
    .handle_read  = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = NULL,
};

void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage  client_addr;
    socklen_t                client_addr_len = sizeof(client_addr);
    struct socks5           *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                              &client_addr_len);
    if (client == -1) {
        // sin conexión lista o interrumpido por señal: no es un error fatal
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    if (fcntl(client, F_SETFD, FD_CLOEXEC) == -1) {
        goto fail;
    }
#ifdef SO_NOSIGPIPE
    // f38 (opcional, macOS/BSD): defensa extra anti-SIGPIPE a nivel socket,
    // redundante con el SIG_IGN global (main.c) y MSG_NOSIGNAL. No fatal si falla.
    (void) setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
    state = socks5_new(client);
    if (state == NULL) {
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;
    state->id              = ++conn_counter;
    {
        char human[SOCKADDR_TO_HUMAN_MIN];
        sockaddr_to_human(human, sizeof(human),
                          (struct sockaddr *) &state->client_addr);
        DBG("[conn #%u] accept desde %s", state->id, human);
    }
    if (selector_register(key->s, client, &socks5_handler, OP_READ, state)
            != SELECTOR_SUCCESS) {
        goto fail;
    }
    metrics_connection_opened();
    return;
fail:
    if (client != -1) {
        close(client);
    }
    socks5_unref(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
/** callback del parser: aplica la política A (elegir USERPASS si se ofrece) */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    struct hello_st *d = p->data;
    if (d->noffered < N(d->offered)) {
        d->offered[d->noffered] = method;
    }
    d->noffered++;
    if (method == SOCKS_HELLO_USERPASS) {
        d->method = SOCKS_HELLO_USERPASS;
    }
}

static void
hello_read_init(const unsigned state, struct selector_key *key) {
    (void) state;
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    d->rb       = &ATTACHMENT(key)->read_buffer;
    d->wb       = &ATTACHMENT(key)->write_buffer;
    d->method   = SOCKS_HELLO_NO_ACCEPTABLE_METHODS;   // default: rechazar
    d->noffered = 0;
    d->parser.data                     = d;
    d->parser.on_authentication_method = on_hello_method;
    hello_parser_init(&d->parser);
}

/** procesa el saludo completo: serializa la respuesta del servidor */
static unsigned
hello_process(struct hello_st *d) {
    if (hello_marshall(d->wb, d->method) == -1) {
        return ERROR;
    }
    return HELLO_WRITE;
}

/** formatea los métodos ofrecidos como "[00, 02]" para el log */
static void
fmt_methods(char *out, size_t outsz, const uint8_t *m, uint8_t n) {
    size_t pos = 0;
    int    w   = snprintf(out + pos, outsz - pos, "[");
    if (w > 0) pos += (size_t) w;
    for (uint8_t i = 0; i < n && pos < outsz; i++) {
        w = snprintf(out + pos, outsz - pos, "%s%02x", i ? ", " : "", m[i]);
        if (w > 0) pos += (size_t) w;
    }
    if (pos < outsz) {
        snprintf(out + pos, outsz - pos, "]");
    }
}

/* tamaño del buffer de log de métodos: hasta N(offered) métodos formateados como
 * "xx, " (4 chars) más '[', ']' y el NUL final (f35: derivado de offered[]). */
#define HELLO_METHODS_LOG_SZ (N(((struct hello_st *)0)->offered) * 4 + 3)

static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d     = &ATTACHMENT(key)->client.hello;
    unsigned         ret   = HELLO_READ;
    bool             error = false;

    size_t   count;
    uint8_t *ptr = buffer_write_ptr(d->rb, &count);
    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if (error) {   // f19: error resuelto inline, simétrico con auth/request_drive
            DBG("[conn #%u] hello: saludo inválido, cierra",
                ATTACHMENT(key)->id);
            return ERROR;
        }
        if (hello_is_done(st, 0)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = hello_process(d);
                const uint8_t shown = d->noffered < (uint8_t) N(d->offered)
                                    ? d->noffered : (uint8_t) N(d->offered);
                char ms[HELLO_METHODS_LOG_SZ];
                fmt_methods(ms, sizeof(ms), d->offered, shown);
                DBG("[conn #%u] hello: ofrece %s -> elige 0x%02x%s",
                    ATTACHMENT(key)->id, ms, d->method,
                    d->method == SOCKS_HELLO_USERPASS ? " (user/pass)"
                                                      : " (NO_ACCEPTABLE, cierra)");
            } else {
                ret = ERROR;
            }
        }
    } else if (n == 0) {
        ret = ERROR;   // el cliente cerró antes de completar el saludo
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        ret = ERROR;   // EINTR: señal; mantenemos estado y reintentamos luego
    }
    return ret;
}

static unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d   = &ATTACHMENT(key)->client.hello;
    unsigned         ret = HELLO_WRITE;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);   // f37: uniforme
    if (n > 0) {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            // respuesta del HELLO enviada por completo.
            if (d->method == SOCKS_HELLO_USERPASS) {
                ret = hello_to_auth(key);   // RFC1929: arrancamos la autenticación
            } else {
                ret = DONE;                 // 0xFF NO_ACCEPTABLE: cerrar (RFC1928 §3)
            }
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        ret = ERROR;   // EINTR: señal; mantenemos estado y reintentamos luego
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// AUTH (sub-handshake usuario/contraseña, RFC1929)

/** valida credenciales, serializa la respuesta y pasa a AUTH_WRITE */
static unsigned
auth_process(struct auth_st *d, struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    const bool ok = users_validate_len(d->parser.uname, d->parser.ulen,
                                       d->parser.passwd, d->parser.plen);
    d->status = ok ? AUTH_STATUS_OK : AUTH_STATUS_FAIL;
    if (ok) {
        const size_t ulen = d->parser.ulen < sizeof(s->username) - 1
                          ? d->parser.ulen : sizeof(s->username) - 1;
        memcpy(s->username, d->parser.uname, ulen);
        s->username[ulen] = '\0';
    }
    DBG("[conn #%u] auth: ulen=%u -> %s", s->id,
        (unsigned)d->parser.ulen, ok ? "OK" : "RECHAZADO");
    if (auth_marshall(d->wb, d->status) == -1
            || selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return AUTH_WRITE;
}

/**
 * Motor de AUTH_READ: PRIMERO drena lo que ya esté en read_buffer (el cliente
 * pudo pipelinear HELLO+AUTH en un mismo segmento; el selector no re-avisa por
 * bytes ya bufferizados), y sólo si falta hace recv. Sin esto la conexión se
 * colgaría (no hay reaper de idle). Lo invocan tanto la transición desde HELLO
 * como los eventos de lectura posteriores.
 */
static unsigned
auth_drive(struct selector_key *key) {
    struct auth_st *d     = &ATTACHMENT(key)->client.auth;
    bool            error = false;

    enum auth_state st = auth_consume(d->rb, &d->parser, &error);   // 1) buffer
    if (!error && !auth_is_done(st, 0)) {                           // 2) socket
        size_t   count;
        uint8_t *ptr = buffer_write_ptr(d->rb, &count);
        if (count == 0) {
            return AUTH_READ;   // buffer lleno (defensivo): esperar, no recv(...,0)
        }
        const ssize_t n = recv(key->fd, ptr, count, 0);
        if (n > 0) {
            buffer_write_adv(d->rb, n);
            st = auth_consume(d->rb, &d->parser, &error);
        } else if (n == 0) {
            return ERROR;   // el cliente cerró antes de completar
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return ERROR;
        }
    }

    if (error) {   // VER != 0x01 (D7.8): responder 01 01 y cerrar, uniforme con la falla
        d->status = AUTH_STATUS_FAIL;
        DBG("[conn #%u] auth: versión inválida -> 01 01, cierra", ATTACHMENT(key)->id);
        if (auth_marshall(d->wb, d->status) == -1
                || selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return AUTH_WRITE;
    }
    if (auth_is_done(st, 0)) {
        return auth_process(d, key);
    }
    return AUTH_READ;   // parcial: esperar más bytes
}

/** entrada a la autenticación tras enviar la respuesta del HELLO */
static unsigned
hello_to_auth(struct selector_key *key) {
    struct auth_st *a = &ATTACHMENT(key)->client.auth;   // clobbea el union (hello ya terminó)
    a->rb     = &ATTACHMENT(key)->read_buffer;
    a->wb     = &ATTACHMENT(key)->write_buffer;
    a->status = AUTH_STATUS_FAIL;
    auth_parser_init(&a->parser);
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return auth_drive(key);   // procesa de una lo pipelined; si no, queda en AUTH_READ
}

static unsigned
auth_read(struct selector_key *key) {
    return auth_drive(key);
}

static unsigned
auth_write(struct selector_key *key) {
    struct auth_st *d   = &ATTACHMENT(key)->client.auth;
    unsigned        ret = AUTH_WRITE;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);   // f37: uniforme
    if (n > 0) {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            // RFC1929 exige cerrar tras STATUS != OK; si autenticó, sigue REQUEST.
            ret = d->status == AUTH_STATUS_OK ? auth_to_request(key) : DONE;
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        ret = ERROR;
    }
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
// REQUEST + CONNECT (RFC1928 §4-§6)

static selector_status
client_set_interest(struct selector_key *key, const fd_interest interest) {
    const struct socks5 *s = ATTACHMENT(key);
    if (s->client_fd == -1) {
        return SELECTOR_IARGS;
    }
    return selector_set_interest(key->s, s->client_fd, interest);
}

static void
request_store_access_target(struct socks5 *s, const struct request *r) {
    s->dest_port = ntohs(r->dst_port);

    if (r->atyp == REQUEST_ATYP_DOMAINNAME) {
        const size_t len = r->dst_fqdn_len < sizeof(s->dest_host) - 1
                         ? r->dst_fqdn_len : sizeof(s->dest_host) - 1;
        memcpy(s->dest_host, r->dst_fqdn, len);
        s->dest_host[len] = '\0';
        return;
    }

    const int family = r->atyp == REQUEST_ATYP_IPV4 ? AF_INET
                     : r->atyp == REQUEST_ATYP_IPV6 ? AF_INET6 : AF_UNSPEC;
    if (family == AF_UNSPEC
            || inet_ntop(family, r->dst_addr,
                         s->dest_host, sizeof(s->dest_host)) == NULL) {
        s->dest_host[0] = '-';
        s->dest_host[1] = '\0';
    }
}

static void
request_log_access_once(struct selector_key *key, const uint8_t rep) {
    struct socks5 *s = ATTACHMENT(key);
    if (s->access_logged || s->dest_host[0] == '\0') {
        return;
    }

    const enum access_result result = rep == REQUEST_REP_SUCCEEDED
                                    ? ACCESS_OK : ACCESS_FAIL;
    logger_log_access(s->username,
                      (const struct sockaddr *) &s->client_addr,
                      s->dest_host, s->dest_port, result);
    s->access_logged = true;
    if (result == ACCESS_FAIL) {
        metrics_connection_failed();
    }
}

static unsigned
request_reply(struct selector_key *key,
              const uint8_t rep,
              const struct sockaddr *bound_addr) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    d->rep = rep;
    buffer_reset(d->wb);
    if (request_marshall_addr(d->wb, rep, bound_addr) == -1
            || client_set_interest(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    request_log_access_once(key, rep);
    return REQUEST_WRITE;
}

static void
request_read_init(const unsigned state, struct selector_key *key) {
    (void) state;
    struct request_st *d = &ATTACHMENT(key)->client.request;
    if (d->initialized) {
        return;
    }
    d->rb          = &ATTACHMENT(key)->read_buffer;
    d->wb          = &ATTACHMENT(key)->write_buffer;
    d->rep         = REQUEST_REP_GENERAL_FAILURE;
    d->initialized = true;
    request_parser_init(&d->parser);
    buffer_reset(d->wb);
    ATTACHMENT(key)->resolv.started = false;
    ATTACHMENT(key)->resolv.gai_error = 0;
    ATTACHMENT(key)->resolv.sys_errno = 0;
}

static int
request_start_connect(struct selector_key *key,
                      const struct sockaddr *addr,
                      const socklen_t addr_len,
                      const int family,
                      const int socktype,
                      const int protocol,
                      uint8_t *rep) {
    struct socks5 *s = ATTACHMENT(key);

    if (request_connect_addr(key->s, &socks5_origin_handler, s, addr, addr_len,
                             family, socktype, protocol, &s->origin_fd, rep)
            == -1) {
        return -1;
    }

    socks5_ref(s);
    if (client_set_interest(key, OP_READ) != SELECTOR_SUCCESS) {
        (void) selector_unregister_fd(key->s, s->origin_fd);
        return -2;
    }
    s->connecting.rep = REQUEST_REP_GENERAL_FAILURE;
    DBG("[conn #%u] request: connect en progreso fd=%d", s->id, s->origin_fd);
    return 0;
}

static unsigned
request_connect_sockaddr(struct selector_key *key,
                         const struct sockaddr *addr,
                         const socklen_t addr_len,
                         const int family,
                         const int socktype,
                         const int protocol) {
    uint8_t rep = REQUEST_REP_GENERAL_FAILURE;
    const int ret = request_start_connect(key, addr, addr_len, family, socktype,
                                          protocol, &rep);
    if (ret == -2) {
        return ERROR;
    }
    if (ret == -1) {
        return request_reply(key, rep, NULL);
    }
    return REQUEST_CONNECTING;
}

static unsigned
request_connect_next(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    while (s->current_resolution != NULL) {
        const struct addrinfo *ai = s->current_resolution;
        s->current_resolution = s->current_resolution->ai_next;
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }
        const int ret = request_start_connect(key, ai->ai_addr,
                                              (socklen_t) ai->ai_addrlen,
                                              ai->ai_family, ai->ai_socktype,
                                              ai->ai_protocol,
                                              &s->connecting.rep);
        if (ret == 0) {
            return REQUEST_CONNECTING;
        }
        if (ret == -2) {
            return ERROR;
        }
    }
    return request_reply(key, s->connecting.rep, NULL);
}

static unsigned
request_process(struct selector_key *key) {
    struct request_st     *d = &ATTACHMENT(key)->client.request;
    const struct request  *r = &d->parser.request;
    request_store_access_target(ATTACHMENT(key), r);

    if (r->atyp == REQUEST_ATYP_IPV4) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr.s_addr, r->dst_addr, 4);
        addr.sin_port = r->dst_port;
        return request_connect_sockaddr(key, (struct sockaddr *) &addr, sizeof(addr),
                                        AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if (r->atyp == REQUEST_ATYP_IPV6) {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        memcpy(&addr6.sin6_addr, r->dst_addr, 16);
        addr6.sin6_port = r->dst_port;
        return request_connect_sockaddr(key, (struct sockaddr *) &addr6, sizeof(addr6),
                                        AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    }
    if (r->atyp == REQUEST_ATYP_DOMAINNAME) {
        return REQUEST_RESOLV;
    }
    return request_reply(key, REQUEST_REP_ATYP_NOT_SUPPORTED, NULL);
}

static unsigned
request_drive(struct selector_key *key) {
    struct request_st *d     = &ATTACHMENT(key)->client.request;
    bool               error = false;

    enum request_state st = request_consume(d->rb, &d->parser, &error);
    if (!error && !request_is_done(st, 0)) {
        size_t   count;
        uint8_t *ptr = buffer_write_ptr(d->rb, &count);
        if (count == 0) {
            return REQUEST_READ;
        }
        const ssize_t n = recv(key->fd, ptr, count, 0);
        if (n > 0) {
            buffer_write_adv(d->rb, n);
            st = request_consume(d->rb, &d->parser, &error);
        } else if (n == 0) {
            return ERROR;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return ERROR;
        }
    }

    if (error) {
        // f21: VER inválida en el REQUEST -> cerrar SIN responder, igual que
        // HELLO. Serializar un frame VER=0x05 a un cliente que justamente NO
        // habla SOCKS5 es semánticamente inútil (RFC1928 no define REP para
        // versión inválida). El resto de los errores de protocolo sí responden
        // con su REP. Decisión documentada en docs/extras/DECISIONS.md.
        if (st == request_error_invalid_version) {
            DBG("[conn #%u] request: VER inválida -> cierre sin responder",
                ATTACHMENT(key)->id);
            return ERROR;
        }
        const uint8_t rep = request_state_rep(st);
        DBG("[conn #%u] request: parseo inválido -> REP 0x%02x",
            ATTACHMENT(key)->id, rep);
        return request_reply(key, rep, NULL);
    }
    if (request_is_done(st, 0)) {
        return request_process(key);
    }
    return REQUEST_READ;
}

static unsigned
auth_to_request(struct selector_key *key) {
    struct request_st *r = &ATTACHMENT(key)->client.request;   // clobbea AUTH
    memset(r, 0, sizeof(*r));
    request_read_init(REQUEST_READ, key);
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return request_drive(key);
}

static unsigned
request_read(struct selector_key *key) {
    return request_drive(key);
}

/*
 * f39: partición de escritura de resolv.gai_error / origin_resolution.
 *   - Si resolv_dispatch() == 0: el hilo DNS arrancó. SÓLO el hilo escribe
 *     gai_error (retorno de getaddrinfo, código EAI_*) y origin_resolution;
 *     main NO los vuelve a tocar. El hilo despierta a main con notify_block.
 *   - Si resolv_dispatch() == -1: el hilo NO existe (resolv.c retornó antes de
 *     pthread_create). SÓLO main escribe gai_error (= EAI_FAIL) y notifica.
 * Así nunca hay dos escritores concurrentes del mismo campo. Códigos en el
 * espacio EAI_* (usar gai_strerror, no strerror, si se loguea).
 *
 * f41: client_set_interest(OP_NOOP) y resolv_dispatch se separan en dos if
 * explícitos (antes un solo if con ||) para que el orden y el balance de
 * refs/notify sean obvios: el hilo se lanza SÓLO con el cliente ya en OP_NOOP.
 */
static void
request_resolv_init(const unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;

    if (s->resolv.started) {
        return;
    }
    s->resolv.started = true;

    // 1) parkear al cliente: durante REQUEST_RESOLV no leemos/escribimos su fd.
    if (client_set_interest(key, OP_NOOP) != SELECTOR_SUCCESS) {
        s->resolv.gai_error = EAI_FAIL;             // sólo main escribe (hilo no existe)
        (void) selector_notify_block(key->s, s->client_fd);
        return;
    }
    // 2) lanzar el hilo DNS. Si falla, el hilo no arrancó: main marca el error.
    if (resolv_dispatch(key, d->parser.request.dst_fqdn,
                        d->parser.request.dst_port) == -1) {
        s->resolv.gai_error = EAI_FAIL;             // sólo main escribe (hilo no existe)
        (void) selector_notify_block(key->s, s->client_fd);
    }
}

static unsigned
request_resolv_done(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);

    /*
     * f15: blindaje de la ventana de reuso de fd. selector_notify_block()
     * despacha el block por NÚMERO de fd, no por objeto: si el cliente se
     * desconectara durante getaddrinfo y su fd se reasignara a otra conexión
     * antes de procesar el job, este callback podría dispararse sobre un objeto
     * que NO está resolviendo. Sólo actuamos si esta conexión realmente lanzó
     * una resolución (resolv.started); en caso contrario ignoramos el block y
     * dejamos a la STM en su estado actual (ver resolv.c para la suposición).
     */
    if (!s->resolv.started) {
        DBG("[conn #%u] request: block de DNS espurio (fd reusado), ignorado",
            s->id);
        return stm_state(&s->stm);   // sin transición: dejamos la STM como está
    }

    if (s->resolv.gai_error != 0 || s->origin_resolution == NULL) {
        const uint8_t rep = s->resolv.gai_error == 0
                          ? REQUEST_REP_GENERAL_FAILURE
                          : request_resolve_error_rep(s->resolv.gai_error,
                                                      s->resolv.sys_errno);
        DBG("[conn #%u] request: resolucion falla gai=%d",
            s->id, s->resolv.gai_error);
        return request_reply(key, rep, NULL);
    }
    s->current_resolution = s->origin_resolution;
    s->connecting.rep = REQUEST_REP_HOST_UNREACHABLE;
    DBG("[conn #%u] request: resolucion OK", s->id);
    return request_connect_next(key);
}

/*
 * Parquea datos que el cliente envía ANTES de que el connect al origin termine
 * (no se pierden: se acumulan en read_buffer). Si read_buffer se llena, ponemos
 * al cliente en OP_NOOP: es backpressure INTENCIONAL, no un deadlock. El interés
 * se RE-ENGANCHA al entrar a COPY: copy_init -> copy_compute_pair recalcula el
 * interés de ambos sentidos tras el buffer_compact, así que los bytes parkeados
 * se drenan hacia el origin apenas arranca el relay.
 */
static unsigned
request_connecting_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    size_t   count;
    uint8_t *ptr = buffer_write_ptr(d->rb, &count);
    if (count == 0) {
        // buffer lleno antes de conectar: backpressure (ver doc arriba).
        return client_set_interest(key, OP_NOOP) == SELECTOR_SUCCESS
             ? REQUEST_CONNECTING : ERROR;
    }

    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->rb, n);
        if (!buffer_can_write(d->rb)) {
            // se llenó al leer: backpressure hasta COPY (ver doc arriba).
            if (client_set_interest(key, OP_NOOP) != SELECTOR_SUCCESS) {
                return ERROR;
            }
        }
        return REQUEST_CONNECTING;
    }
    if (n == 0) {
        return DONE;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return REQUEST_CONNECTING;
    }
    return ERROR;
}

static unsigned
request_connecting(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    int            so_error = 0;
    socklen_t      so_len   = sizeof(so_error);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) == -1) {
        so_error = errno;
    }

    if (so_error == 0) {
        struct sockaddr_storage bound;
        socklen_t               bound_len = sizeof(bound);
        memset(&bound, 0, sizeof(bound));
        if (getsockname(key->fd, (struct sockaddr *) &bound, &bound_len) == -1
                || (bound.ss_family != AF_INET && bound.ss_family != AF_INET6)) {
            // f16: getsockname casi nunca falla sobre un socket conectado; si
            // pasa, usamos la dirección destino como BND.ADDR (RFC1928 espera la
            // dirección del socket, pero el destino es mejor aproximación que
            // 0.0.0.0:0). Último recurso documentado: 0.0.0.0:0.
            DBG("[conn #%u] request: getsockname falló (errno=%d), "
                "uso addr destino como BND", s->id, errno);
            memset(&bound, 0, sizeof(bound));
            // El addr destino de este intento está parkeado en el socket;
            // getpeername lo refleja. Si tampoco anda, último recurso 0.0.0.0:0.
            socklen_t peer_len = sizeof(bound);
            if (getpeername(key->fd, (struct sockaddr *) &bound, &peer_len) == -1
                    || (bound.ss_family != AF_INET
                        && bound.ss_family != AF_INET6)) {
                memset(&bound, 0, sizeof(bound));
                bound.ss_family = AF_INET;
            }
        }
        // El origin_fd se deja registrado en OP_NOOP a propósito, parkeado para la
        // fase COPY de M4. El interés del cliente se arma vía request_reply ->
        // client_set_interest, que resuelve s->client_fd (NO key->fd): durante
        // REQUEST_CONNECTING el key activo es el del origin_fd, no el del cliente.
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        s->connecting.rep = REQUEST_REP_SUCCEEDED;
        socks5_resolution_clear(s);
        DBG("[conn #%u] request: connect OK", s->id);
        return request_reply(key, REQUEST_REP_SUCCEEDED,
                             (const struct sockaddr *) &bound);
    }

    s->connecting.rep = request_connect_errno_rep(so_error);
    DBG("[conn #%u] request: connect falla errno=%d -> REP 0x%02x",
        s->id, so_error, s->connecting.rep);
    // f11: desregistramos el origin fallido. selector_unregister_fd dispara
    // socksv5_close, que cierra el fd y pone s->origin_fd=-1. Pero NO podemos
    // depender de ese efecto (si el unregister falla, socksv5_close no corre):
    // nulamos origin_fd y cerramos defensivamente acá, así el snapshot de
    // socksv5_done no reintenta unregister sobre un fd ya consumido (evita f10).
    if (s->origin_fd != -1) {
        const int origin_fd = s->origin_fd;
        if (selector_unregister_fd(key->s, origin_fd) != SELECTOR_SUCCESS) {
            // unregister no corrió handle_close (socksv5_close): el fd sigue
            // abierto y la ref que tomó request_start_connect no se liberó.
            // Cerramos, nulamos y soltamos la ref a mano (no fatal, no aborta).
            if (s->origin_fd != -1) {
                close(origin_fd);
                s->origin_fd = -1;
                socks5_unref(s);
            }
        }
    }
    if (s->current_resolution != NULL) {
        return request_connect_next(key);
    }
    return request_reply(key, s->connecting.rep, NULL);
}

static unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if (count == 0) {
        return d->rep == REQUEST_REP_SUCCEEDED ? COPY : DONE;
    }

    const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n > 0) {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            return d->rep == REQUEST_REP_SUCCEEDED ? COPY : DONE;
        }
    } else if (n == -1
            && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

////////////////////////////////////////////////////////////////////////////////
// Handlers top-level: emiten los eventos a la máquina de estados
static void socksv5_done(struct selector_key *key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state  st  = stm_handler_read(stm, key);
    if (st == ERROR || st == DONE) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state  st  = stm_handler_write(stm, key);
    if (st == ERROR || st == DONE) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state  st  = stm_handler_block(stm, key);
    if (st == ERROR || st == DONE) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    // El cierre del fd se centraliza en handle_close: así también se cierran
    // los fds de conexiones activas durante el apagado (selector_destroy ->
    // selector_unregister_fd -> handle_close), evitando fugas. socksv5_done
    // sólo desregistra; el close() real ocurre acá, una sola vez por fd.
    struct socks5 *s = ATTACHMENT(key);
    if (key->fd == s->client_fd) {
        metrics_connection_closed();
        s->client_fd = -1;
    } else if (key->fd == s->origin_fd) {
        s->origin_fd = -1;
    }
    close(key->fd);
    socks5_unref(s);
}

static void
socksv5_done(struct selector_key *key) {
    DBG("[conn #%u] cierre", ATTACHMENT(key)->id);
    // Snapshot de ambos fds ANTES del loop de unregister, a propósito:
    // selector_unregister_fd dispara socksv5_close, que muta los campos fd del
    // struct y puede devolverlo al pool; iterar sobre los campos vivos sería inseguro.
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            // unregister dispara handle_close (socksv5_close), que cierra el fd.
            // f10: un fallo (p.ej. SELECTOR_IARGS si el fd ya fue consumido por
            // otra ruta, como el cierre defensivo de request_connecting) NO es
            // fatal: el fd ya está cerrado/fuera del selector. Logueamos y
            // seguimos en vez de abort() (que mataría TODAS las conexiones).
            const selector_status us = selector_unregister_fd(key->s, fds[i]);
            if (us != SELECTOR_SUCCESS) {
                DBG("[conn #%u] cierre: unregister fd=%d devolvió %d (ignorado)",
                    ATTACHMENT(key)->id, fds[i], us);
            }
        }
    }
}
