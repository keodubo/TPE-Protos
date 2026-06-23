/**
 * socks5nio.c — máquina de estados de una conexión SOCKS5 (no bloqueante).
 *
 * MILESTONE M1: implementa la negociación de método (HELLO, RFC1928 §3).
 * Los handlers top-level (socksv5_read/write) delegan en la `stm`; cuando la
 * máquina llega a DONE o ERROR se desregistran y cierran los fds.
 *
 * Estados siguientes (M2+): tras HELLO con método USERPASS se insertará
 * AUTH_READ/AUTH_WRITE (ver TODO en hello_write).
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
#include "dbg.h"
#include "socks5nio.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

/** estados de la máquina de la conexión cliente. DEBEN ser correlativos. */
enum socks_v5state {
    HELLO_READ  = 0,   // lee y procesa el saludo del cliente
    HELLO_WRITE,       // envía la selección de método
    // TODO M2: AUTH_READ, AUTH_WRITE
    // TODO M3: REQUEST_READ, REQUEST_CONNECTING, REQUEST_WRITE
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
    } client;

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
static void socksv5_close(struct selector_key *key);

static const struct fd_handler socks5_handler = {
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
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ret = ERROR;
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
            // respuesta enviada por completo.
            // TODO M2: si d->method == SOCKS_HELLO_USERPASS -> AUTH_READ
            //          (set_interest OP_READ). Por ahora cerramos.
            ret = DONE;
        }
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ret = ERROR;
    }
    return ret;
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
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
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
            if (selector_unregister_fd(key->s, fds[i]) != SELECTOR_SUCCESS) {
                abort();
            }
            close(fds[i]);
        }
    }
}
