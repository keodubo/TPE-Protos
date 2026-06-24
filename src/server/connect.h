#ifndef CONNECT_H_TPE_SOCKS5
#define CONNECT_H_TPE_SOCKS5

#include <stdint.h>
#include <sys/socket.h>

#include "selector.h"
#include "request.h"

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

int
request_connect_addr(fd_selector s,
                     const struct fd_handler *origin_handler,
                     void *data,
                     const struct sockaddr *addr,
                     socklen_t addr_len,
                     int ai_family,
                     int ai_socktype,
                     int ai_protocol,
                     int *origin_fd,
                     uint8_t *rep);

#endif
