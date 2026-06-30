/*
 * mgmt.c - Protocolo de Monitoreo y Configuracion (PMC).
 *
 * M7 handshake: listener no bloqueante, STM propia, parser de lineas CRLF y
 * autenticacion de administrador. Los comandos post-auth se agregan en el
 * siguiente corte.
 */
#include "mgmt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "buffer.h"
#include "dbg.h"
#include "selector.h"
#include "socks5.h"   /* MSG_NOSIGNAL portable */
#include "stm.h"

#define MGMT_BUFFER_SIZE 1024
#define MGMT_LINE_MAX    512
#define MGMT_LINE_TEXT_MAX (MGMT_LINE_MAX - 2)

enum mgmt_state {
    MGMT_GREETING = 0,
    MGMT_AUTH,
    MGMT_REQUEST,
    MGMT_DONE,
    MGMT_ERROR,
};

struct mgmt_conn {
    int                  fd;
    struct state_machine stm;

    buffer               read_buf;
    buffer               write_buf;
    uint8_t              raw_read[MGMT_BUFFER_SIZE];
    uint8_t              raw_write[MGMT_BUFFER_SIZE];

    char                 line[MGMT_LINE_TEXT_MAX + 1];
    size_t               line_len;
    bool                 saw_cr;
    bool                 discarding;
    bool                 line_too_long_reported;

    enum mgmt_state      after_write;
};

static const char *admin_user = "admin";
static const char *admin_pass = "s3cr3t";

static void     mgmt_read_dispatch (struct selector_key *key);
static void     mgmt_write_dispatch(struct selector_key *key);
static void     mgmt_close         (struct selector_key *key);
static unsigned mgmt_state_read    (struct selector_key *key);
static unsigned mgmt_state_write   (struct selector_key *key);

static const struct state_definition mgmt_statbl[] = {
    {
        .state          = MGMT_GREETING,
        .on_read_ready  = mgmt_state_read,
        .on_write_ready = mgmt_state_write,
    }, {
        .state          = MGMT_AUTH,
        .on_read_ready  = mgmt_state_read,
        .on_write_ready = mgmt_state_write,
    }, {
        .state          = MGMT_REQUEST,
        .on_read_ready  = mgmt_state_read,
        .on_write_ready = mgmt_state_write,
    }, {
        .state = MGMT_DONE,
    }, {
        .state = MGMT_ERROR,
    },
};

static const struct fd_handler mgmt_handler = {
    .handle_read  = mgmt_read_dispatch,
    .handle_write = mgmt_write_dispatch,
    .handle_close = mgmt_close,
    .handle_block = NULL,
};

void
mgmt_init(const char *user, const char *pass) {
    admin_user = user == NULL ? "admin" : user;
    admin_pass = pass == NULL ? "s3cr3t" : pass;
}

static struct mgmt_conn *
mgmt_new(const int fd) {
    struct mgmt_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }
    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->after_write = MGMT_GREETING;

    conn->stm.initial = MGMT_GREETING;
    conn->stm.max_state = MGMT_ERROR;
    conn->stm.states = mgmt_statbl;
    stm_init(&conn->stm);

    buffer_init(&conn->read_buf, sizeof(conn->raw_read), conn->raw_read);
    buffer_init(&conn->write_buf, sizeof(conn->raw_write), conn->raw_write);
    return conn;
}

static void
mgmt_close(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;
    close(key->fd);
    free(conn);
}

static void
mgmt_done(struct selector_key *key) {
    (void) selector_unregister_fd(key->s, key->fd);
}

static bool
mgmt_queue(struct mgmt_conn *conn, const char *response) {
    const size_t len = strlen(response);
    size_t count;
    uint8_t *dst = buffer_write_ptr(&conn->write_buf, &count);
    if (count < len) {
        return false;
    }
    memcpy(dst, response, len);
    buffer_write_adv(&conn->write_buf, (ssize_t) len);
    return true;
}

static void
mgmt_set_response(struct mgmt_conn *conn,
                  const char *response,
                  const enum mgmt_state next) {
    if (!mgmt_queue(conn, response)) {
        conn->after_write = MGMT_ERROR;
        return;
    }
    conn->after_write = next;
}

static int
mgmt_split(char *line, char *argv[], const int max_args) {
    int argc = 0;
    char *p = line;

    while (*p != '\0') {
        if (argc == max_args) {
            return -1;
        }
        argv[argc++] = p;
        while (*p != '\0' && *p != ' ') {
            p++;
        }
        if (*p == ' ') {
            *p++ = '\0';
            if (*p == '\0') {
                return -1;
            }
        }
    }
    return argc;
}

static enum mgmt_state
mgmt_handle_line(struct mgmt_conn *conn, const enum mgmt_state current) {
    char *argv[4];
    const int argc = mgmt_split(conn->line, argv, 4);

    if (current == MGMT_GREETING) {
        if (argc == 2 && strcmp(argv[0], "HELLO") == 0) {
            if (strcmp(argv[1], "1") == 0) {
                mgmt_set_response(conn, "+OK 1\r\n", MGMT_AUTH);
            } else {
                mgmt_set_response(conn, "-ERR unsupported version\r\n", MGMT_DONE);
            }
        } else {
            mgmt_set_response(conn, "-ERR not authenticated\r\n", MGMT_GREETING);
        }
        return current;
    }

    if (current == MGMT_AUTH) {
        if (argc == 3 && strcmp(argv[0], "AUTH") == 0) {
            if (strcmp(argv[1], admin_user) == 0
                    && strcmp(argv[2], admin_pass) == 0) {
                mgmt_set_response(conn, "+OK\r\n", MGMT_REQUEST);
            } else {
                mgmt_set_response(conn, "-ERR auth failed\r\n", MGMT_DONE);
            }
        } else {
            mgmt_set_response(conn, "-ERR not authenticated\r\n", MGMT_AUTH);
        }
        return current;
    }

    if (current == MGMT_REQUEST) {
        if (argc == 1 && strcmp(argv[0], "QUIT") == 0) {
            mgmt_set_response(conn, "+OK bye\r\n", MGMT_DONE);
        } else {
            mgmt_set_response(conn, "-ERR not implemented\r\n", MGMT_REQUEST);
        }
        return current;
    }

    return MGMT_ERROR;
}

static enum mgmt_state
mgmt_line_complete(struct mgmt_conn *conn, const enum mgmt_state current) {
    conn->line[conn->line_len] = '\0';
    conn->line_len = 0;
    conn->saw_cr = false;
    return mgmt_handle_line(conn, current);
}

static enum mgmt_state
mgmt_process_buffer(struct mgmt_conn *conn, enum mgmt_state current) {
    while (buffer_can_read(&conn->read_buf)
            && !buffer_can_read(&conn->write_buf)) {
        const uint8_t c = buffer_read(&conn->read_buf);

        if (conn->discarding) {
            if (c == '\n') {
                conn->discarding = false;
                conn->line_too_long_reported = false;
                conn->line_len = 0;
                conn->saw_cr = false;
            }
            continue;
        }

        if (conn->saw_cr) {
            if (c == '\n') {
                current = mgmt_line_complete(conn, current);
                continue;
            }
            if (conn->line_len >= MGMT_LINE_TEXT_MAX) {
                mgmt_set_response(conn, "-ERR line too long\r\n", current);
                conn->discarding = true;
                conn->line_too_long_reported = true;
                continue;
            }
            conn->line[conn->line_len++] = '\r';
            conn->saw_cr = false;
        }

        if (c == '\r') {
            conn->saw_cr = true;
        } else if (conn->line_len >= MGMT_LINE_TEXT_MAX) {
            if (!conn->line_too_long_reported) {
                mgmt_set_response(conn, "-ERR line too long\r\n", current);
                conn->line_too_long_reported = true;
            }
            conn->discarding = true;
        } else {
            conn->line[conn->line_len++] = (char) c;
        }
    }
    return current;
}

static unsigned
mgmt_state_read(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;
    enum mgmt_state current = (enum mgmt_state) stm_state(&conn->stm);

    size_t count;
    uint8_t *ptr = buffer_write_ptr(&conn->read_buf, &count);
    if (count == 0) {
        return MGMT_ERROR;
    }

    const ssize_t n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(&conn->read_buf, n);
        current = mgmt_process_buffer(conn, current);
        if (buffer_can_read(&conn->write_buf)) {
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return MGMT_ERROR;
            }
        }
        return current;
    }
    if (n == 0) {
        return MGMT_DONE;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return current;
    }
    return MGMT_ERROR;
}

static unsigned
mgmt_state_write(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;

    size_t count;
    uint8_t *ptr = buffer_read_ptr(&conn->write_buf, &count);
    if (count > 0) {
        const ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(&conn->write_buf, n);
        } else if (n == -1
                && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return MGMT_ERROR;
        }
    }

    if (buffer_can_read(&conn->write_buf)) {
        return stm_state(&conn->stm);
    }
    if (conn->after_write == MGMT_DONE || conn->after_write == MGMT_ERROR) {
        return conn->after_write;
    }
    enum mgmt_state next = conn->after_write;
    if (buffer_can_read(&conn->read_buf)) {
        next = mgmt_process_buffer(conn, next);
        if (buffer_can_read(&conn->write_buf)) {
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                return MGMT_ERROR;
            }
            return next;
        }
    }
    if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
        return MGMT_ERROR;
    }
    conn->after_write = next;
    return next;
}

static void
mgmt_read_dispatch(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;
    const enum mgmt_state st = stm_handler_read(&conn->stm, key);
    if (st == MGMT_DONE || st == MGMT_ERROR) {
        mgmt_done(key);
    }
}

static void
mgmt_write_dispatch(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;
    const enum mgmt_state st = stm_handler_write(&conn->stm, key);
    if (st == MGMT_DONE || st == MGMT_ERROR) {
        mgmt_done(key);
    }
}

void
mgmt_passive_accept(struct selector_key *key) {
    int client = -1;
    struct mgmt_conn *conn = NULL;

    client = accept(key->fd, NULL, NULL);
    if (client == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }
        return;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    if (fcntl(client, F_SETFD, FD_CLOEXEC) == -1) {
        goto fail;
    }

    conn = mgmt_new(client);
    if (conn == NULL) {
        goto fail;
    }

    if (selector_register(key->s, client, &mgmt_handler, OP_READ, conn)
            != SELECTOR_SUCCESS) {
        goto fail;
    }
    DBG("[mgmt] accept fd=%d", client);
    return;

fail:
    if (client != -1) {
        close(client);
    }
    free(conn);
}
