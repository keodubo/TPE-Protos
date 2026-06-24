/*
 * connect.c - helper para CONNECT IPv4 no bloqueante (M3).
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "connect.h"

uint8_t
request_connect_errno_rep(const int error) {
    switch (error) {
        case ENETUNREACH:
            return REQUEST_REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
        case ETIMEDOUT:
            return REQUEST_REP_HOST_UNREACHABLE;
        case ECONNREFUSED:
            return REQUEST_REP_CONNECTION_REFUSED;
        default:
            return REQUEST_REP_GENERAL_FAILURE;
    }
}

int
request_connect_addr(fd_selector s,
                     const struct fd_handler *origin_handler,
                     void *data,
                     const struct sockaddr *addr,
                     const socklen_t addr_len,
                     const int ai_family,
                     const int ai_socktype,
                     const int ai_protocol,
                     int *origin_fd,
                     uint8_t *rep) {
    if (rep != NULL) {
        *rep = REQUEST_REP_GENERAL_FAILURE;
    }
    if (origin_fd != NULL) {
        *origin_fd = -1;
    }

    const int fd = socket(ai_family, ai_socktype, ai_protocol);
    if (fd == -1) {
        if (rep != NULL) {
            *rep = request_connect_errno_rep(errno);
        }
        return -1;
    }

    if (selector_fd_set_nio(fd) == -1) {
        if (rep != NULL) {
            *rep = REQUEST_REP_GENERAL_FAILURE;
        }
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        if (rep != NULL) {
            *rep = REQUEST_REP_GENERAL_FAILURE;
        }
        close(fd);
        return -1;
    }

    if (connect(fd, addr, addr_len) == -1
            && errno != EINPROGRESS && errno != EINTR) {
        if (rep != NULL) {
            *rep = request_connect_errno_rep(errno);
        }
        close(fd);
        return -1;
    }

    if (selector_register(s, fd, origin_handler, OP_WRITE, data)
            != SELECTOR_SUCCESS) {
        if (rep != NULL) {
            *rep = REQUEST_REP_GENERAL_FAILURE;
        }
        close(fd);
        return -1;
    }

    if (origin_fd != NULL) {
        *origin_fd = fd;
    }
    return 0;
}

int
request_connect_ipv4(fd_selector s,
                     const struct fd_handler *origin_handler,
                     void *data,
                     const struct request *request,
                     int *origin_fd,
                     uint8_t *rep) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, request->dst_addr, 4);
    addr.sin_port = request->dst_port;

    return request_connect_addr(s, origin_handler, data,
                                (const struct sockaddr *) &addr, sizeof(addr),
                                AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                origin_fd, rep);
}
