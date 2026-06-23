#ifndef CONNECT_H_TPE_SOCKS5
#define CONNECT_H_TPE_SOCKS5

#include <stdint.h>

#include "selector.h"
#include "request.h"

#define REQUEST_REP_NETWORK_UNREACHABLE     0x03
#define REQUEST_REP_HOST_UNREACHABLE        0x04
#define REQUEST_REP_CONNECTION_REFUSED      0x05

uint8_t
request_connect_errno_rep(int error);

/*
 * Inicia un connect(2) no bloqueante para un REQUEST IPv4 literal.
 * Retorna 0 si origin_fd quedo registrado en el selector con OP_WRITE.
 * Retorna -1 si fallo antes de registrar; en ese caso *rep contiene el REP.
 */
int
request_connect_ipv4(fd_selector s,
                     const struct fd_handler *origin_handler,
                     void *data,
                     const struct request *request,
                     int *origin_fd,
                     uint8_t *rep);

#endif
