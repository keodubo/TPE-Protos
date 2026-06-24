#ifndef SOCKS5_H_TPE_SOCKS5
#define SOCKS5_H_TPE_SOCKS5

#include <stdbool.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/socket.h>

#include "auth.h"
#include "buffer.h"
#include "copy.h"
#include "hello.h"
#include "request.h"
#include "socks5nio.h"
#include "stm.h"

enum socks_v5state {
    HELLO_READ  = 0,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
};

struct hello_st {
    buffer              *rb, *wb;
    struct hello_parser  parser;
    uint8_t              method;
    uint8_t              offered[8];
    uint8_t              noffered;
};

struct auth_st {
    buffer              *rb, *wb;
    struct auth_parser   parser;
    uint8_t              status;
};

struct request_st {
    buffer                *rb, *wb;
    struct request_parser  parser;
    uint8_t                rep;
    bool                   initialized;
};

struct connecting_st {
    uint8_t                rep;
};

struct resolv_st {
    bool                   started;
    int                    gai_error;
};

struct socks5 {
    int                     client_fd;
    int                     origin_fd;

    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    unsigned                id;

    struct state_machine    stm;

    union {
        struct hello_st      hello;
        struct auth_st       auth;
        struct request_st    request;
    } client;

    struct connecting_st    connecting;
    struct resolv_st        resolv;
    struct copy             copy_client;
    struct copy             copy_origin;

    struct addrinfo        *origin_resolution;
    struct addrinfo        *current_resolution;

    uint8_t                 raw_buff_a[IO_BUFFER_SIZE];
    uint8_t                 raw_buff_b[IO_BUFFER_SIZE];
    buffer                  read_buffer;
    buffer                  write_buffer;

    unsigned                references;
    struct socks5          *next;
};

void socks5_ref(struct socks5 *s);
void socks5_unref(struct socks5 *s);

#endif
