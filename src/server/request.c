/*
 * request.c - parser/serializador del REQUEST SOCKS5 (RFC1928).
 * Maquina de bytes a mano, sin I/O.
 */
#include <string.h>

#include "request.h"

static bool
request_fqdn_char_allowed(const uint8_t b) {
    return b >= 0x21 && b != 0x7F;
}

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
                p->request.dst_addr_len = 4;
                p->state    = request_dst_addr;
            } else if (b == REQUEST_ATYP_IPV6) {
                p->addr_idx = 0;
                p->request.dst_addr_len = 16;
                p->state    = request_dst_addr;
            } else if (b == REQUEST_ATYP_DOMAINNAME) {
                p->state = request_fqdn_len;
            } else {
                p->state = request_error_unsupported_atyp;
            }
            break;
        case request_fqdn_len:
            p->request.dst_fqdn_len = b;
            p->request.dst_addr_len = b;
            p->addr_idx = 0;
            if (b == 0) {
                p->state = request_error_unsupported_atyp;
            } else {
                p->state = request_dst_addr;
            }
            break;
        case request_dst_addr:
            if (p->request.atyp == REQUEST_ATYP_DOMAINNAME) {
                if (!request_fqdn_char_allowed(b)) {
                    p->state = request_error_unsupported_atyp;
                    break;
                }
                p->request.dst_fqdn[p->addr_idx] = (char)b;
            } else {
                p->request.dst_addr[p->addr_idx] = b;
            }
            p->addr_idx++;
            if (p->addr_idx == p->request.dst_addr_len) {
                if (p->request.atyp == REQUEST_ATYP_DOMAINNAME) {
                    p->request.dst_fqdn[p->addr_idx] = '\0';
                }
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

/*
 * Mapea un estado terminal del parser a su REP SOCKS5. En produccion el caller
 * (request_drive en socks5nio.c) la invoca en la rama de error (errored==true);
 * el camino de exito serializa su REP por separado (request_process). Aun asi
 * incluimos case request_done -> 0x00 (success) para que la funcion sea total
 * sobre los estados terminales y verificable de forma blackbox.
 *
 * Notas RFC1928:
 * - VER != 0x05 (request_error_invalid_version): este case existe por completitud
 *   del switch, pero NO se ejercita en producción. request_drive (socks5nio.c)
 *   intercepta la versión inválida ANTES de llamar a request_state_rep y CIERRA
 *   sin responder (uniforme con HELLO), porque el cliente no habla SOCKS5 y el RFC
 *   no define REP para versión inválida. Decisión D8.1 en DECISIONS.md.
 * - RSV != 0x00 (request_error_invalid_reserved): validacion estricta (el RFC
 *   exige RSV==0x00). No hay REP especifico, asi que cae en GENERAL_FAILURE.
 *   Decision documentada en DECISIONS.md.
 */
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

static int
request_marshall_ipv4(buffer *b, const uint8_t rep, const struct sockaddr_in *bound_addr) {
    size_t   n;
    uint8_t *p = buffer_write_ptr(b, &n);
    if (n < REQUEST_REPLY_IPV4_LEN) {
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
    buffer_write_adv(b, REQUEST_REPLY_IPV4_LEN);
    return REQUEST_REPLY_IPV4_LEN;
}

static int
request_marshall_ipv6(buffer *b, const uint8_t rep, const struct sockaddr_in6 *bound_addr) {
    size_t   n;
    uint8_t *p = buffer_write_ptr(b, &n);
    if (n < REQUEST_REPLY_IPV6_LEN) {
        return -1;
    }

    p[0] = REQUEST_SOCKS_VERSION;
    p[1] = rep;
    p[2] = REQUEST_RSV;
    p[3] = REQUEST_ATYP_IPV6;
    if (bound_addr == NULL) {
        memset(p + 4, 0, 18);
    } else {
        memcpy(p + 4, &bound_addr->sin6_addr, 16);
        memcpy(p + 20, &bound_addr->sin6_port, 2);
    }
    buffer_write_adv(b, REQUEST_REPLY_IPV6_LEN);
    return REQUEST_REPLY_IPV6_LEN;
}

int
request_marshall_addr(buffer *b, const uint8_t rep, const struct sockaddr *bound_addr) {
    if (bound_addr != NULL && bound_addr->sa_family == AF_INET6) {
        return request_marshall_ipv6(b, rep, (const struct sockaddr_in6 *)bound_addr);
    }
    return request_marshall_ipv4(b, rep, (const struct sockaddr_in *)bound_addr);
}
