#ifndef SOCKS5NIO_H_TPE_SOCKS5
#define SOCKS5NIO_H_TPE_SOCKS5

#include <stdbool.h>
#include <stddef.h>

#include "selector.h"
#include "request.h"   /* REQUEST_REPLY_IPV4_LEN / REQUEST_REPLY_IPV6_LEN */

/**
 * Tamaño de los buffers de I/O por conexión.
 * NO es un número mágico: se elige midiendo (ver docs/extras/buffer-sizing.md).
 * Sobreescribible sin tocar el código:
 *   make CFLAGS_EXTRA=-DIO_BUFFER_SIZE=16384
 */
#ifndef IO_BUFFER_SIZE
#define IO_BUFFER_SIZE 8192
#endif

/*
 * Piso de cordura para el buffer de escritura: request_marshall_addr() necesita
 * REQUEST_REPLY_IPV4_LEN (10) bytes libres para la reply IPv4 y
 * REQUEST_REPLY_IPV6_LEN (22) para la IPv6 (peor caso). Con menos espacio el
 * marshall falla y el server cerraría sin responder al REQUEST. El default 8192
 * nunca lo alcanza; este #error es sólo una red de seguridad para overrides
 * agresivos de IO_BUFFER_SIZE.
 */
#if IO_BUFFER_SIZE < REQUEST_REPLY_IPV6_LEN
#error "IO_BUFFER_SIZE debe ser >= REQUEST_REPLY_IPV6_LEN (22)"
#endif

#define IO_BUFFER_SIZE_MIN REQUEST_REPLY_IPV6_LEN
#define IO_BUFFER_SIZE_MAX (1024 * 1024)

/** tamaño vigente para buffers de nuevas conexiones SOCKS5 */
size_t
socksv5_buffer_size(void);

/**
 * Cambia el tamaño para conexiones nuevas. No redimensiona conexiones activas.
 * Devuelve false si está fuera de [IO_BUFFER_SIZE_MIN, IO_BUFFER_SIZE_MAX].
 */
bool
socksv5_buffer_size_set(size_t size);

/** handler del socket pasivo SOCKS: acepta la conexión y arranca la stm */
void
socksv5_passive_accept(struct selector_key *key);

/** libera el pool de objetos de conexión (llamar durante el apagado) */
void
socksv5_pool_destroy(void);

#endif
