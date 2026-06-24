/*
 * connect.c - helper para CONNECT no bloqueante generico (IPv4/IPv6), M3+M5.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "connect.h"

uint8_t
request_connect_errno_rep(const int error) {
    switch (error) {
        case EACCES:
        case EPERM:
            /* firewall/politica local rechaza la conexion saliente */
            return REQUEST_REP_CONNECTION_NOT_ALLOWED;
        case ENETUNREACH:
        case ENETDOWN:
            return REQUEST_REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
        case ETIMEDOUT:
            return REQUEST_REP_HOST_UNREACHABLE;
        case ECONNREFUSED:
            return REQUEST_REP_CONNECTION_REFUSED;
        default:
            /* default consciente: cualquier otro errno (incluido EINPROGRESS
             * inesperado, EAFNOSUPPORT, etc.) se reporta como fallo general.
             * 0x01 es un REP valido del RFC1928 para errores no mapeados. */
            return REQUEST_REP_GENERAL_FAILURE;
    }
}

uint8_t
request_resolve_error_rep(const int gai_error, const int system_error) {
    switch (gai_error) {
        case 0:
            return REQUEST_REP_SUCCEEDED;
        case EAI_SYSTEM:
            return request_connect_errno_rep(system_error);
        case EAI_MEMORY:
            return REQUEST_REP_GENERAL_FAILURE;
        default:
            return REQUEST_REP_HOST_UNREACHABLE;
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
