/*
 * mgmt.c - esqueleto del Protocolo de Monitoreo y Configuracion (PMC).
 *
 * M7 primer corte: el server ya expone un segundo listener no bloqueante en el
 * mismo selector. El handshake y los comandos del protocolo se implementan en
 * los siguientes cortes.
 */
#include "mgmt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "dbg.h"
#include "selector.h"

struct mgmt_conn {
    int fd;
};

static void
mgmt_close(struct selector_key *key) {
    struct mgmt_conn *conn = key->data;
    if (conn != NULL) {
        close(conn->fd);
        free(conn);
    } else {
        close(key->fd);
    }
}

static void
mgmt_done(struct selector_key *key) {
    (void) selector_unregister_fd(key->s, key->fd);
}

static void
mgmt_read(struct selector_key *key) {
    /*
     * El protocolo todavia no esta activo en este corte. Cerramos limpio ante
     * cualquier intento de hablar para no dejar fds vivos.
     */
    mgmt_done(key);
}

static void
mgmt_write(struct selector_key *key) {
    mgmt_done(key);
}

static const struct fd_handler mgmt_handler = {
    .handle_read  = mgmt_read,
    .handle_write = mgmt_write,
    .handle_close = mgmt_close,
    .handle_block = NULL,
};

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

    conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        goto fail;
    }
    conn->fd = client;

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
