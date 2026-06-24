#ifndef CONNECT_H_TPE_SOCKS5
#define CONNECT_H_TPE_SOCKS5

#include <stdint.h>
#include <sys/socket.h>

#include "selector.h"
#include "request.h"

uint8_t
request_connect_errno_rep(int error);

uint8_t
request_resolve_error_rep(int gai_error, int system_error);

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
