/**
 * socks5nio.c — máquina de estados de una conexión SOCKS5 (no bloqueante).
 *
 * M1: negociación de método (HELLO, RFC1928 §3).
 * M2: autenticación usuario/contraseña (AUTH, RFC1929).
 * Los handlers top-level (socksv5_read/write) delegan en la `stm`; cuando la
 * máquina llega a DONE o ERROR se desregistran y cierran los fds.
 *
 * M3: REQUEST + CONNECT IPv4 literal; el relay/COPY queda para M4.
 */
#include <stdlib.h>   // malloc
#include <string.h>   // memset
#include <stdint.h>   // uint8_t (buffer.h lo usa pero no lo incluye)
#include <stdbool.h>
#include <errno.h>
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
#include "users.h"
#include "dbg.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** estados de la máquina de la conexión cliente. DEBEN ser correlativos. */
enum socks_v5state {
    HELLO_READ  = 0,   // lee y procesa el saludo del cliente
    HELLO_WRITE,       // envía la selección de método
    AUTH_READ,         // lee el sub-handshake usuario/contraseña (RFC1929)
    AUTH_WRITE,        // envía VER STATUS de la autenticación
    REQUEST_READ,      // lee y procesa REQUEST (RFC1928 §4)
    REQUEST_CONNECTING,// espera resultado del connect no bloqueante
    REQUEST_WRITE,     // envía REP al cliente
    // TODO M4: COPY
    DONE,
    ERROR,
};

/** variables de los estados HELLO_READ / HELLO_WRITE */
struct hello_st {
    buffer              *rb, *wb;
    struct hello_parser  parser;
    /** método elegido por el servidor (USERPASS o NO_ACCEPTABLE) */
    uint8_t              method;
    /** métodos ofrecidos por el cliente (para el log de debug) */
    uint8_t              offered[8];
    uint8_t              noffered;
};

/** variables de los estados AUTH_READ / AUTH_WRITE (RFC1929) */
struct auth_st {
    buffer              *rb, *wb;
    struct auth_parser   parser;
    uint8_t              status;   // 0x00 ok / 0x01 fail
};

/** variables de REQUEST_READ / REQUEST_WRITE (RFC1928) */
struct request_st {
    buffer                *rb, *wb;
    struct request_parser  parser;
    uint8_t                rep;
    bool                   initialized;
};

/** variables de REQUEST_CONNECTING */
struct connecting_st {
    uint8_t                rep;
};

/** una conexión SOCKS5; se aloca una vez por cliente y se reusa vía pool. */
struct socks5 {
    int                  client_fd;
    int                  origin_fd;

    /** dirección del cliente (para logs) e id de conexión */
    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    unsigned                id;

    struct state_machine stm;

    /** estados sobre el client_fd */
    union {
        struct hello_st  hello;
        struct auth_st   auth;
        struct request_st request;
    } client;

    struct connecting_st connecting;

    /** buffers de I/O */
    uint8_t              raw_buff_a[IO_BUFFER_SIZE];
    uint8_t              raw_buff_b[IO_BUFFER_SIZE];
    buffer               read_buffer;
    buffer               write_buffer;

    /** contador de referencias y free-list del pool */
    unsigned             references;
    struct socks5       *next;
};

////////////////////////////////////////////////////////////////////////////////
// Pool de objetos (reusar alocaciones para sostener muchas conexiones)
static struct socks5  *pool      = NULL;
static unsigned        pool_size = 0;
static const unsigned  max_pool  = 50;

/** contador de conexiones (para identificarlas en los logs) */
static unsigned        conn_counter = 0;

static const struct state_definition *socks5_describe_states(void);

/** entrada a la autenticación desde HELLO_WRITE (definida en la sección AUTH) */
static unsigned hello_to_auth(struct selector_key *key);
static unsigned auth_to_request(struct selector_key *key);

static struct socks5 *
socks5_new(const int client_fd) {
    struct socks5 *ret;
    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret       = pool;
        pool      = pool->next;
        pool_size--;
    }
    if (ret == NULL) {
        return NULL;
    }
    memset(ret, 0, sizeof(*ret));
    ret->client_fd  = client_fd;
    ret->origin_fd  = -1;
    ret->references = 1;

    ret->stm.initial   = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states    = socks5_describe_states();
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer,  N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    return ret;
}

static void
socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        return;
    }
    if (s->references == 1) {
        if (pool_size < max_pool) {
            s->next    = pool;
            pool       = s;
            pool_size++;
        } else {
            free(s);
        }
    } else {
        s->references--;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s = pool;
    while (s != NULL) {
        next = s->next;
        free(s);
        s = next;
    }
    pool      = NULL;
    pool_size = 0;
}

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

////////////////////////////////////////////////////////////////////////////////
// Handlers de selección de una conexión establecida
static void socksv5_read (struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_origin_write(struct selector_key *key);
static void socksv5_close(struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read  = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = NULL,
};

static const struct fd_handler socks5_origin_handler = {
    .handle_read  = NULL,
    .handle_write = socksv5_origin_write,
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
    return;
fail:
    if (client != -1) {
        close(client);
    }
    socks5_destroy(state);
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
        if (error) {
            DBG("[conn #%u] hello: saludo inválido (¿versión?), cierra",
                ATTACHMENT(key)->id);
        } else if (hello_is_done(st, 0)) {
            if (selector_set_interest_key(key, OP_WRITE) == SELECTOR_SUCCESS) {
                ret = hello_process(d);
                const uint8_t shown = d->noffered < (uint8_t) N(d->offered)
                                    ? d->noffered : (uint8_t) N(d->offered);
                char ms[8 * 4 + 3];
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
    return error ? ERROR : ret;
}

static unsigned
hello_write(struct selector_key *key) {
    struct hello_st *d   = &ATTACHMENT(key)->client.hello;
    unsigned         ret = HELLO_WRITE;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    const ssize_t n = send(key->fd, ptr, count, 0);
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
    const bool ok = users_validate_len(d->parser.uname, d->parser.ulen,
                                       d->parser.passwd, d->parser.plen);
    d->status = ok ? AUTH_STATUS_OK : AUTH_STATUS_FAIL;
    DBG("[conn #%u] auth: ulen=%u -> %s", ATTACHMENT(key)->id,
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
    const ssize_t n = send(key->fd, ptr, count, 0);
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
// REQUEST + CONNECT IPv4 literal (RFC1928 §4-§6)

static selector_status
client_set_interest(struct selector_key *key, const fd_interest interest) {
    const struct socks5 *s = ATTACHMENT(key);
    if (s->client_fd == -1) {
        return SELECTOR_IARGS;
    }
    return selector_set_interest(key->s, s->client_fd, interest);
}

static unsigned
request_reply(struct selector_key *key,
              const uint8_t rep,
              const struct sockaddr_in *bound_addr) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    d->rep = rep;
    buffer_reset(d->wb);
    if (request_marshall(d->wb, rep, bound_addr) == -1
            || client_set_interest(key, OP_WRITE) != SELECTOR_SUCCESS) {
        return ERROR;
    }
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
}

static unsigned
request_process(struct selector_key *key) {
    struct socks5     *s = ATTACHMENT(key);
    struct request_st *d = &s->client.request;
    uint8_t            rep = REQUEST_REP_GENERAL_FAILURE;

    s->references++;
    if (request_connect_ipv4(key->s, &socks5_origin_handler, s,
                             &d->parser.request, &s->origin_fd, &rep) == -1) {
        socks5_destroy(s);  // deshace la referencia especulativa del origin_fd
        DBG("[conn #%u] request: connect inmediato falla -> REP 0x%02x",
            s->id, rep);
        return request_reply(key, rep, NULL);
    }

    if (client_set_interest(key, OP_READ) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    s->connecting.rep = REQUEST_REP_GENERAL_FAILURE;
    DBG("[conn #%u] request: connect en progreso fd=%d", s->id, s->origin_fd);
    return REQUEST_CONNECTING;
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

static unsigned
request_connecting_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    size_t   count;
    uint8_t *ptr = buffer_write_ptr(d->rb, &count);
    if (count == 0) {
        if (client_set_interest(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        return REQUEST_CONNECTING;
    }

    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->rb, n);
        if (!buffer_can_write(d->rb)
                && client_set_interest(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
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
        struct sockaddr_in bound;
        socklen_t          bound_len = sizeof(bound);
        memset(&bound, 0, sizeof(bound));
        bound.sin_family = AF_INET;
        if (getsockname(key->fd, (struct sockaddr *) &bound, &bound_len) == -1
                || bound.sin_family != AF_INET) {
            memset(&bound, 0, sizeof(bound));
            bound.sin_family = AF_INET;
        }
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS) {
            return ERROR;
        }
        s->connecting.rep = REQUEST_REP_SUCCEEDED;
        DBG("[conn #%u] request: connect OK", s->id);
        return request_reply(key, REQUEST_REP_SUCCEEDED, &bound);
    }

    s->connecting.rep = request_connect_errno_rep(so_error);
    DBG("[conn #%u] request: connect falla errno=%d -> REP 0x%02x",
        s->id, so_error, s->connecting.rep);
    if (s->origin_fd != -1
            && selector_unregister_fd(key->s, s->origin_fd) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return request_reply(key, s->connecting.rep, NULL);
}

static unsigned
request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    size_t   count;
    uint8_t *ptr = buffer_read_ptr(d->wb, &count);
    if (count == 0) {
        return DONE;
    }

    const ssize_t n = send(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb)) {
            return DONE;    // M3 estricto: sin relay; M4 reemplaza esto por COPY.
        }
    } else if (n == -1
            && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

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
        .state          = REQUEST_CONNECTING,
        .on_read_ready  = request_connecting_read,
        .on_write_ready = request_connecting,
    }, {
        .state          = REQUEST_WRITE,
        .on_write_ready = request_write,
    }, {
        .state = DONE,
    }, {
        .state = ERROR,
    },
};

static const struct state_definition *
socks5_describe_states(void) {
    return client_statbl;
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
socksv5_origin_write(struct selector_key *key) {
    struct state_machine     *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state  st  = stm_handler_write(stm, key);
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
        s->client_fd = -1;
    } else if (key->fd == s->origin_fd) {
        s->origin_fd = -1;
    }
    close(key->fd);
    socks5_destroy(s);
}

static void
socksv5_done(struct selector_key *key) {
    DBG("[conn #%u] cierre", ATTACHMENT(key)->id);
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            // unregister dispara handle_close (socksv5_close), que cierra el fd
            if (selector_unregister_fd(key->s, fds[i]) != SELECTOR_SUCCESS) {
                abort();
            }
        }
    }
}
