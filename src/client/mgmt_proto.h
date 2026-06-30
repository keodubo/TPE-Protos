#ifndef MGMT_PROTO_H_TPE_SOCKS5
#define MGMT_PROTO_H_TPE_SOCKS5

#include <stddef.h>
#include <stdio.h>

#define MGMT_PROTO_LINE_MAX 512

struct mgmt_reply {
    int  ok;
    char text[MGMT_PROTO_LINE_MAX];
};

int mgmt_connect(const char *host, const char *port);
int mgmt_handshake(int fd, const char *user, const char *pass, FILE *out);
int mgmt_send_line(int fd, const char *line);
int mgmt_read_reply(int fd, struct mgmt_reply *reply, FILE *out);
int mgmt_expect_multiline(int fd, const struct mgmt_reply *reply, FILE *out);

#endif
