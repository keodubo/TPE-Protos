#ifndef HELLO_H_TPE_SOCKS5
#define HELLO_H_TPE_SOCKS5

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

/**
 * hello.c — parser y serializador del saludo SOCKS5 (RFC1928 §3).
 *
 * Cliente:  VER(1)=0x05  NMETHODS(1)  METHODS(NMETHODS)
 * Servidor: VER(1)=0x05  METHOD(1)
 *
 * El parser es incremental: tolera que los bytes lleguen de a poco
 * (lecturas parciales). Por cada método ofrecido invoca un callback.
 */

#define SOCKS_VERSION                      0x05
#define SOCKS_HELLO_NOAUTH                 0x00
#define SOCKS_HELLO_USERPASS               0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS  0xFF

enum hello_state {
    hello_version,                     // esperando el byte VER
    hello_nmethods,                    // esperando el byte NMETHODS
    hello_methods,                     // leyendo los METHODS
    hello_done,                        // saludo completo
    hello_error_unsupported_version,   // VER != 0x05
};

struct hello_parser {
    /** invocado una vez por cada método ofrecido por el cliente */
    void (*on_authentication_method)(struct hello_parser *parser, uint8_t method);
    /** dato del usuario (p. ej. dónde acumular el método elegido) */
    void *data;
    /** estado interno del parser */
    enum hello_state state;
    /** métodos que faltan leer cuando state == hello_methods */
    uint8_t remaining;
};

/** inicializa el parser (estado inicial; NO toca data ni el callback) */
void hello_parser_init(struct hello_parser *p);

/**
 * Consume todos los bytes disponibles en `b`, avanzando el parser e
 * invocando el callback por cada método. Devuelve el estado alcanzado.
 * Si hay error de protocolo, deja *errored = true.
 */
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);

/** true si el parser llegó a un estado final (done o error). */
bool hello_is_done(enum hello_state state, bool *errored);

/**
 * Serializa la respuesta del servidor (VER, METHOD) en `b`.
 * Devuelve la cantidad de bytes escritos (2), o -1 si no hay espacio.
 */
int hello_marshall(buffer *b, uint8_t method);

#endif
