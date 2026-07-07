#include "mgmt_proto.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int
write_all(const int fd, const char *buf, const size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += (size_t) n;
        } else if (n == -1 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int
read_line(const int fd, char *line, const size_t cap) {
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        const ssize_t n = recv(fd, &c, 1, 0);
        if (n == 1) {
            line[len++] = c;
            if (len >= 2 && line[len - 2] == '\r' && line[len - 1] == '\n') {
                line[len - 2] = '\0';
                return 0;
            }
        } else if (n == 0) {
            return -1;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return -1;
}

int
mgmt_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    const int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "client: getaddrinfo: %s\n", gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) {
            continue;
        }
#ifdef SO_NOSIGPIPE
        (void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd == -1) {
        perror("client: connect");
    }
    return fd;
}

int
mgmt_send_line(const int fd, const char *line) {
    return write_all(fd, line, strlen(line));
}

int
mgmt_read_reply(const int fd, struct mgmt_reply *reply, FILE *out) {
    char line[MGMT_PROTO_LINE_MAX];
    if (read_line(fd, line, sizeof(line)) == -1) {
        fprintf(stderr, "client: no se pudo leer respuesta PMC\n");
        return -1;
    }
    if (out != NULL) {
        fprintf(out, "%s\n", line);
    }
    reply->ok = strncmp(line, "+OK", 3) == 0;
    if (strncmp(line, "+OK ", 4) == 0 || strncmp(line, "-ERR ", 5) == 0) {
        const char *text = line[0] == '+' ? line + 4 : line + 5;
        snprintf(reply->text, sizeof(reply->text), "%s", text);
    } else {
        reply->text[0] = '\0';
    }
    return reply->ok ? 0 : 1;
}

int
mgmt_expect_multiline(const int fd, const struct mgmt_reply *reply, FILE *out) {
    char *end = NULL;
    const unsigned long n = strtoul(reply->text, &end, 10);
    if (end == reply->text || *end != '\0') {
        return 0;
    }
    for (unsigned long i = 0; i < n; i++) {
        char line[MGMT_PROTO_LINE_MAX];
        if (read_line(fd, line, sizeof(line)) == -1) {
            fprintf(stderr, "client: respuesta multilinea incompleta\n");
            return -1;
        }
        if (out != NULL) {
            fprintf(out, "%s\n", line);
        }
    }
    return 0;
}

int
mgmt_handshake(const int fd, const char *user, const char *pass, FILE *out) {
    struct mgmt_reply reply;
    char auth[MGMT_PROTO_LINE_MAX];

    if (mgmt_send_line(fd, "HELLO 1\r\n") == -1
            || mgmt_read_reply(fd, &reply, out) != 0) {
        return -1;
    }
    const int n = snprintf(auth, sizeof(auth), "AUTH %s %s\r\n", user, pass);
    if (n < 0 || (size_t) n >= sizeof(auth)) {
        fprintf(stderr, "client: credencial admin demasiado larga\n");
        return -1;
    }
    if (mgmt_send_line(fd, auth) == -1) {
        return -1;
    }
    return mgmt_read_reply(fd, &reply, out) == 0 ? 0 : -1;
}
