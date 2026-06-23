#include "hello.h"

void
hello_parser_init(struct hello_parser *p) {
    p->state     = hello_version;
    p->remaining = 0;
}

/** procesa un único byte, avanzando el estado del parser */
static enum hello_state
hello_parser_feed(struct hello_parser *p, const uint8_t b) {
    switch (p->state) {
        case hello_version:
            p->state = (b == SOCKS_VERSION) ? hello_nmethods
                                            : hello_error_unsupported_version;
            break;
        case hello_nmethods:
            p->remaining = b;
            p->state     = (b == 0) ? hello_done : hello_methods;
            break;
        case hello_methods:
            if (p->on_authentication_method != NULL) {
                p->on_authentication_method(p, b);
            }
            if (--p->remaining == 0) {
                p->state = hello_done;
            }
            break;
        case hello_done:
        case hello_error_unsupported_version:
            break;  // estados finales: no consumimos más
    }
    return p->state;
}

bool
hello_is_done(const enum hello_state state, bool *errored) {
    if (state == hello_error_unsupported_version) {
        if (errored != NULL) *errored = true;
        return true;
    }
    return state == hello_done;
}

enum hello_state
hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state st = p->state;
    if (hello_is_done(st, errored)) {
        return st;   // ya en estado final: no consumir más bytes (M2: pipelining)
    }
    while (buffer_can_read(b)) {
        const uint8_t byte = buffer_read(b);
        st = hello_parser_feed(p, byte);
        if (hello_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

int
hello_marshall(buffer *b, const uint8_t method) {
    size_t   n;
    uint8_t *p = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    p[0] = SOCKS_VERSION;
    p[1] = method;
    buffer_write_adv(b, 2);
    return 2;
}
