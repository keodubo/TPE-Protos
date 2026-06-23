/*
 * request.c - parser/serializador del REQUEST SOCKS5 (RFC1928).
 * Maquina de bytes a mano, sin I/O. M3 solo soporta CONNECT + IPv4.
 */
#include <string.h>

#include "request.h"

void
request_parser_init(struct request_parser *p) {
    p->state    = request_version;
    p->addr_idx = 0;
    p->port[0]  = 0;
    p->port[1]  = 0;
    memset(&p->request, 0, sizeof(p->request));
}

static enum request_state
request_parser_feed(struct request_parser *p, const uint8_t b) {
    switch (p->state) {
        case request_version:
            p->state = (b == REQUEST_SOCKS_VERSION)
                     ? request_cmd
                     : request_error_invalid_version;
            break;
        case request_cmd:
            p->request.cmd = b;
            p->state = (b == REQUEST_CMD_CONNECT)
                     ? request_rsv
                     : request_error_unsupported_command;
            break;
        case request_rsv:
            p->state = (b == REQUEST_RSV)
                     ? request_atyp
                     : request_error_invalid_reserved;
            break;
        case request_atyp:
            p->request.atyp = b;
            if (b == REQUEST_ATYP_IPV4) {
                p->addr_idx = 0;
                p->state    = request_dst_addr;
            } else {
                p->state = request_error_unsupported_atyp;
            }
            break;
        case request_dst_addr:
            p->request.dst_addr[p->addr_idx++] = b;
            if (p->addr_idx == sizeof(p->request.dst_addr)) {
                p->state = request_dst_port_high;
            }
            break;
        case request_dst_port_high:
            p->port[0] = b;
            p->state   = request_dst_port_low;
            break;
        case request_dst_port_low:
            p->port[1] = b;
            memcpy(&p->request.dst_port, p->port, sizeof(p->request.dst_port));
            p->state = request_done;
            break;
        case request_done:
        case request_error_invalid_version:
        case request_error_invalid_reserved:
        case request_error_unsupported_command:
        case request_error_unsupported_atyp:
            break;  /* estados finales: no consumimos mas */
    }
    return p->state;
}

bool
request_is_done(const enum request_state state, bool *errored) {
    switch (state) {
        case request_error_invalid_version:
        case request_error_invalid_reserved:
        case request_error_unsupported_command:
        case request_error_unsupported_atyp:
            if (errored != NULL) *errored = true;
            return true;
        case request_done:
            return true;
        default:
            return false;
    }
}

enum request_state
request_consume(buffer *b, struct request_parser *p, bool *errored) {
    enum request_state st = p->state;
    if (request_is_done(st, errored)) {
        return st;
    }
    while (buffer_can_read(b)) {
        const uint8_t byte = buffer_read(b);
        st = request_parser_feed(p, byte);
        if (request_is_done(st, errored)) {
            break;
        }
    }
    return st;
}

uint8_t
request_state_rep(const enum request_state state) {
    switch (state) {
        case request_done:
            return REQUEST_REP_SUCCEEDED;
        case request_error_unsupported_command:
            return REQUEST_REP_COMMAND_NOT_SUPPORTED;
        case request_error_unsupported_atyp:
            return REQUEST_REP_ATYP_NOT_SUPPORTED;
        case request_error_invalid_version:
        case request_error_invalid_reserved:
        default:
            return REQUEST_REP_GENERAL_FAILURE;
    }
}

int
request_marshall(buffer *b, const uint8_t rep, const struct sockaddr_in *bound_addr) {
    size_t   n;
    uint8_t *p = buffer_write_ptr(b, &n);
    if (n < 10) {
        return -1;
    }

    p[0] = REQUEST_SOCKS_VERSION;
    p[1] = rep;
    p[2] = REQUEST_RSV;
    p[3] = REQUEST_ATYP_IPV4;
    if (bound_addr == NULL) {
        memset(p + 4, 0, 6);
    } else {
        memcpy(p + 4, &bound_addr->sin_addr.s_addr, 4);
        memcpy(p + 8, &bound_addr->sin_port, 2);
    }
    buffer_write_adv(b, 10);
    return 10;
}
