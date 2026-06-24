#ifndef AUTH_H_TPE_SOCKS5
#define AUTH_H_TPE_SOCKS5

/*
 * auth.h — parser/serializador del sub-handshake usuario/contraseña (RFC1929).
 *
 * Mismo patrón que hello.{c,h} (D6): máquina de bytes a mano, sin I/O.
 * El cliente envía:  VER(0x01) ULEN UNAME[ULEN] PLEN PASSWD[PLEN]
 * El servidor responde:  VER(0x01) STATUS   (0x00 éxito / !=0 falla)
 */
#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define AUTH_VERSION      0x01
#define AUTH_STATUS_OK    0x00
#define AUTH_STATUS_FAIL  0x01

/*
 * Límite de campo de RFC1929: ULEN/PLEN viajan en 1 byte, así que UNAME/PASSWD
 * (y los nombres/contraseñas de la tabla de usuarios) miden a lo sumo 255 bytes.
 * Fuente única del número de protocolo; users.c lo reusa vía este header.
 */
#define RFC1929_FIELD_MAX 255
#define AUTH_MAX_FIELD    RFC1929_FIELD_MAX   /* alias histórico (ver RFC1929_FIELD_MAX) */

enum auth_state {
    auth_version,     /* espera VER (debe ser 0x01) */
    auth_ulen,        /* espera ULEN */
    auth_uname,       /* lee ULEN bytes de UNAME */
    auth_plen,        /* espera PLEN */
    auth_passwd,      /* lee PLEN bytes de PASSWD */
    auth_done,        /* request completo */
    auth_error_unsupported_version,   /* VER != 0x01 */
};

struct auth_parser {
    enum auth_state state;
    uint8_t  remaining;                    /* bytes que faltan del campo actual */
    uint8_t  ulen;
    uint8_t  plen;
    uint8_t  uname_idx;
    uint8_t  passwd_idx;
    char     uname[AUTH_MAX_FIELD + 1];    /* NUL-terminado */
    char     passwd[AUTH_MAX_FIELD + 1];   /* NUL-terminado */
};

/** reinicia el parser al estado inicial */
void auth_parser_init(struct auth_parser *p);

/**
 * Drena el buffer alimentando el parser byte a byte hasta terminar o agotar
 * los bytes disponibles. Si ya estaba en estado final, NO consume nada
 * (preserva bytes pipelined, p. ej. el request de M3). Setea *errored si la
 * versión es inválida.
 */
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);

/** true si el parser llegó a un estado final; setea *errored ante VER inválido */
bool auth_is_done(enum auth_state state, bool *errored);

/** serializa la respuesta (VER STATUS). Devuelve 2, o -1 si no hay lugar. */
int auth_marshall(buffer *b, uint8_t status);

#endif
