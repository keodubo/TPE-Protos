/*
 * auth.c — parser/serializador del sub-handshake usuario/contraseña (RFC1929).
 * Máquina de bytes a mano (mismo patrón que hello.c), sin I/O.
 */
#include "auth.h"

void
auth_parser_init(struct auth_parser *p) {
    p->state      = auth_version;
    p->remaining  = 0;
    p->ulen       = 0;
    p->plen       = 0;
    p->uname_idx  = 0;
    p->passwd_idx = 0;
    p->uname[0]   = '\0';
    p->passwd[0]  = '\0';
}

/** procesa un único byte, avanzando el estado del parser */
static enum auth_state
auth_parser_feed(struct auth_parser *p, const uint8_t b) {
    switch (p->state) {
        case auth_version:
            p->state = (b == AUTH_VERSION) ? auth_ulen
                                           : auth_error_unsupported_version;
            break;
        case auth_ulen:
            p->ulen      = b;
            p->uname_idx = 0;
            if (b == 0) {                 // ULEN=0 -> usuario vacío
                p->uname[0] = '\0';
                p->state    = auth_plen;
            } else {
                p->remaining = b;
                p->state     = auth_uname;
            }
            break;
        case auth_uname:
            if (p->uname_idx < AUTH_MAX_FIELD) {
                p->uname[p->uname_idx++] = (char) b;
            }
            if (--p->remaining == 0) {
                p->uname[p->uname_idx] = '\0';
                p->state               = auth_plen;
            }
            break;
        case auth_plen:
            p->plen       = b;
            p->passwd_idx = 0;
            if (b == 0) {                 // PLEN=0 -> contraseña vacía
                p->passwd[0] = '\0';
                p->state     = auth_done;
            } else {
                p->remaining = b;
                p->state     = auth_passwd;
            }
            break;
        case auth_passwd:
            if (p->passwd_idx < AUTH_MAX_FIELD) {
                p->passwd[p->passwd_idx++] = (char) b;
            }
            if (--p->remaining == 0) {
                p->passwd[p->passwd_idx] = '\0';
                p->state                 = auth_done;
            }
            break;
        case auth_done:
        case auth_error_unsupported_version:
            break;  // estados finales: no consumimos más
    }
    return p->state;
}

bool
auth_is_done(const enum auth_state state, bool *errored) {
    if (state == auth_error_unsupported_version) {
        if (errored != NULL) *errored = true;
        return true;
    }
    return state == auth_done;
}

enum auth_state
auth_consume(buffer *b, struct auth_parser *p, bool *errored) {
    enum auth_state st = p->state;
    if (auth_is_done(st, errored)) {
        return st;   // ya en estado final: no consumir más (preserva pipelined)
    }
    while (buffer_can_read(b)) {
        const uint8_t byte = buffer_read(b);
        st = auth_parser_feed(p, byte);
        if (auth_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

int
auth_marshall(buffer *b, const uint8_t status) {
    size_t   n;
    uint8_t *p = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    p[0] = AUTH_VERSION;
    p[1] = status;
    buffer_write_adv(b, 2);
    return 2;
}
