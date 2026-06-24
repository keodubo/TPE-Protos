#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr) {
    /* Bugfix compartido (D6): los helpers del toolkit deben tolerar buffers
     * vacios. Con buffsize==0 no hay byte donde escribir ni terminador posible. */
    if (buffsize == 0) {
        return buff;
    }
    if(addr == 0) {
        snprintf(buff, buffsize, "%s", "null");
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch(addr->sa_family) {
        case AF_INET:
            p    = &((struct sockaddr_in *) addr)->sin_addr;
            port =  ((struct sockaddr_in *) addr)->sin_port;
            handled = true;
            break;
        case AF_INET6:
            p    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            port =  ((struct sockaddr_in6 *) addr)->sin6_port;
            handled = true;
            break;
    }
    /* fix: armamos la IP en un temporal y construimos "ip:puerto" con un unico
     * snprintf acotado a buffsize. Antes se usaba strncat(buff, ":", buffsize)
     * pasando el tamano TOTAL del buffer (deberia ser el restante,
     * buffsize-strlen(buff)-1), patron incorrecto/peligroso de la API. */
    char ip[INET6_ADDRSTRLEN];
    if(handled) {
        if (inet_ntop(addr->sa_family, p, ip, sizeof(ip)) == 0) {
            snprintf(ip, sizeof(ip), "%s", "unknown ip");
        }
        snprintf(buff, buffsize, "%s:%d", ip, ntohs(port));
    } else {
        snprintf(buff, buffsize, "%s", "unknown");
    }

    return buff;
}

int
sock_blocking_write(const int fd, buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}
