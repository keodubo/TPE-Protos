#ifndef SOCKS5NIO_H_TPE_SOCKS5
#define SOCKS5NIO_H_TPE_SOCKS5

#include "selector.h"

/**
 * Tamaño de los buffers de I/O por conexión.
 * NO es un número mágico: se elige midiendo (ver docs/extras/buffer-sizing.md).
 * Sobreescribible sin tocar el código:
 *   make CFLAGS_EXTRA=-DIO_BUFFER_SIZE=16384
 */
#ifndef IO_BUFFER_SIZE
#define IO_BUFFER_SIZE 8192
#endif

/* piso de cordura: la respuesta del REQUEST (IPv4) necesita 10 bytes libres;
 * con menos, request_marshall() falla y el server cerraría sin responder. */
#if IO_BUFFER_SIZE < 10
#error "IO_BUFFER_SIZE debe ser >= 10"
#endif

/** handler del socket pasivo SOCKS: acepta la conexión y arranca la stm */
void
socksv5_passive_accept(struct selector_key *key);

/** libera el pool de objetos de conexión (llamar durante el apagado) */
void
socksv5_pool_destroy(void);

#endif
