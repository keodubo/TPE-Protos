#ifndef REQUEST_H_TPE_SOCKS5
#define REQUEST_H_TPE_SOCKS5

/*
 * request.h - parser/serializador del REQUEST SOCKS5 (RFC1928).
 *
 * M3 estricto: parser incremental, sin I/O, solo ATYP=IPv4.
 * Cliente:  VER(0x05) CMD RSV(0x00) ATYP DST.ADDR DST.PORT
 * Servidor: VER(0x05) REP RSV(0x00) ATYP BND.ADDR BND.PORT
 */
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "buffer.h"

#define REQUEST_SOCKS_VERSION              0x05
#define REQUEST_CMD_CONNECT                0x01
#define REQUEST_ATYP_IPV4                  0x01
#define REQUEST_RSV                        0x00

#define REQUEST_REP_SUCCEEDED              0x00
#define REQUEST_REP_GENERAL_FAILURE        0x01
#define REQUEST_REP_NETWORK_UNREACHABLE     0x03
#define REQUEST_REP_HOST_UNREACHABLE        0x04
#define REQUEST_REP_CONNECTION_REFUSED      0x05
#define REQUEST_REP_COMMAND_NOT_SUPPORTED  0x07
#define REQUEST_REP_ATYP_NOT_SUPPORTED     0x08

enum request_state {
    request_version,                    /* espera VER (debe ser 0x05) */
    request_cmd,                        /* espera CMD (solo CONNECT) */
    request_rsv,                        /* espera RSV (debe ser 0x00) */
    request_atyp,                       /* espera ATYP (solo IPv4) */
    request_dst_addr,                   /* lee 4 bytes de DST.ADDR */
    request_dst_port_high,              /* lee byte alto de DST.PORT */
    request_dst_port_low,               /* lee byte bajo de DST.PORT */
    request_done,                       /* request completo */
    request_error_invalid_version,      /* VER != 0x05 */
    request_error_invalid_reserved,     /* RSV != 0x00 */
    request_error_unsupported_command,  /* CMD != CONNECT */
    request_error_unsupported_atyp,     /* ATYP != IPv4 */
};

struct request {
    uint8_t  cmd;
    uint8_t  atyp;
    uint8_t  dst_addr[4];
    uint16_t dst_port;                  /* bytes en network byte order */
};

struct request_parser {
    enum request_state state;
    struct request     request;
    uint8_t            addr_idx;
    uint8_t            port[2];
};

/** reinicia el parser al estado inicial y borra la request parseada */
void request_parser_init(struct request_parser *p);

/**
 * Drena el buffer alimentando el parser byte a byte hasta terminar o agotar
 * los bytes disponibles. Si ya estaba en estado final, NO consume nada
 * (preserva bytes pipelined para M4+). Setea *errored ante errores de protocolo.
 */
enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored);

/** true si el parser llego a done o a un error final */
bool request_is_done(enum request_state state, bool *errored);

/** mapea el estado final a REP SOCKS5 */
uint8_t request_state_rep(enum request_state state);

/** serializa VER REP RSV ATYP BND.ADDR BND.PORT. Devuelve 10, o -1 sin espacio. */
int request_marshall(buffer *b, uint8_t rep, const struct sockaddr_in *bound_addr);

#endif
