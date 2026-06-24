#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

#include "copy.h"
#include "socks5.h"   /* ATTACHMENT y el fallback de MSG_NOSIGNAL viven acá (f26) */

static struct copy *
copy_for_key(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    if (key->fd == s->client_fd) {
        return &s->copy_client;
    }
    if (key->fd == s->origin_fd) {
        return &s->copy_origin;
    }
    return NULL;
}

/* key.fd se refresca por evento (puede cambiar al reusar fds). key.data (el
 * struct socks5) es invariante por conexión y se fija una sola vez en copy_init. */
static void
copy_set_key(struct copy *c, struct selector_key *key) {
    c->key.s  = key->s;
    c->key.fd = c->fd == NULL ? -1 : *c->fd;
}

static void
copy_shutdown_write(struct copy *c) {
    if (c != NULL && (c->duplex & OP_WRITE) && c->fd != NULL && *c->fd != -1) {
        (void) shutdown(*c->fd, SHUT_WR);
        c->duplex = INTEREST_OFF(c->duplex, OP_WRITE);
    }
}

static void
copy_maybe_shutdown_peer(struct copy *c) {
    if (c != NULL && !(c->duplex & OP_READ) && !buffer_can_read(c->rb)) {
        copy_shutdown_write(c->other);
    }
}

static selector_status
copy_compute_pair(struct copy *c) {
    selector_status st = copy_compute_interests(c);
    if (st == SELECTOR_SUCCESS) {
        st = copy_compute_interests(c->other);
    }
    return st;
}

static unsigned
copy_next_state(struct socks5 *s) {
    if (!(s->copy_client.duplex & OP_READ)
            && !(s->copy_origin.duplex & OP_READ)
            && !buffer_can_read(&s->read_buffer)
            && !buffer_can_read(&s->write_buffer)) {
        return DONE;
    }
    return COPY;
}

selector_status
copy_compute_interests(struct copy *c) {
    fd_interest interest = OP_NOOP;

    if (c == NULL || c->fd == NULL || *c->fd == -1) {
        return SELECTOR_IARGS;
    }
    c->key.fd = *c->fd;
    if ((c->duplex & OP_READ) && buffer_can_write(c->rb)) {
        interest |= OP_READ;
    }
    if ((c->duplex & OP_WRITE) && buffer_can_read(c->wb)) {
        interest |= OP_WRITE;
    }
    return selector_set_interest_key(&c->key, interest);
}

void
copy_init(const unsigned state, struct selector_key *key) {
    (void) state;
    struct socks5 *s = ATTACHMENT(key);

    buffer_compact(&s->read_buffer);
    buffer_compact(&s->write_buffer);

    s->copy_client.fd        = &s->client_fd;
    s->copy_client.rb        = &s->read_buffer;
    s->copy_client.wb        = &s->write_buffer;
    s->copy_client.duplex    = OP_READ | OP_WRITE;
    s->copy_client.other     = &s->copy_origin;
    s->copy_client.key.data  = key->data;   /* invariante por conexión */
    copy_set_key(&s->copy_client, key);

    s->copy_origin.fd        = &s->origin_fd;
    s->copy_origin.rb        = &s->write_buffer;
    s->copy_origin.wb        = &s->read_buffer;
    s->copy_origin.duplex    = OP_READ | OP_WRITE;
    s->copy_origin.other     = &s->copy_client;
    s->copy_origin.key.data  = key->data;   /* invariante por conexión */
    copy_set_key(&s->copy_origin, key);

    (void) copy_compute_pair(&s->copy_client);
}

unsigned
copy_read(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy   *c = copy_for_key(key);

    if (c == NULL) {
        return ERROR;
    }
    copy_set_key(c, key);

    size_t   count = 0;
    uint8_t *ptr   = buffer_write_ptr(c->rb, &count);
    if (count > 0) {
        const ssize_t n = recv(*c->fd, ptr, count, 0);
        if (n > 0) {
            buffer_write_adv(c->rb, n);
        } else if (n == 0) {
            c->duplex = INTEREST_OFF(c->duplex, OP_READ);
            copy_maybe_shutdown_peer(c);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return ERROR;
        }
    }

    copy_maybe_shutdown_peer(c);
    if (copy_compute_pair(c) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return copy_next_state(s);
}

unsigned
copy_write(struct selector_key *key) {
    struct socks5 *s = ATTACHMENT(key);
    struct copy   *c = copy_for_key(key);

    if (c == NULL) {
        return ERROR;
    }
    copy_set_key(c, key);

    size_t   count = 0;
    uint8_t *ptr   = buffer_read_ptr(c->wb, &count);
    if (count > 0) {
        const ssize_t n = send(*c->fd, ptr, count, MSG_NOSIGNAL);
        if (n > 0) {
            buffer_read_adv(c->wb, n);
        } else if (n == -1
                && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return ERROR;
        }
    }

    copy_maybe_shutdown_peer(c->other);
    if (copy_compute_pair(c) != SELECTOR_SUCCESS) {
        return ERROR;
    }
    return copy_next_state(s);
}
