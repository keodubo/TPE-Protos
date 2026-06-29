#ifndef LOGGER_H_TPE_SOCKS5
#define LOGGER_H_TPE_SOCKS5

#include <stdio.h>
#include <sys/socket.h>

enum access_result {
    ACCESS_OK,
    ACCESS_FAIL,
};

void logger_init(FILE *out);
void logger_log_access(const char *username,
                       const struct sockaddr *client,
                       const char *dest_host,
                       unsigned dest_port,
                       enum access_result result);

#endif
