#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "resolv.h"
#include "socks5.h"

struct resolv_args {
    fd_selector    selector;
    int            client_fd;
    struct socks5 *socks;
    char           name[REQUEST_FQDN_MAX + 1];
    char           service[6];
};

static void *
resolv_blocking(void *data) {
    struct resolv_args *args = data;
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const int ret = getaddrinfo(args->name, args->service, &hints, &res);
    args->socks->resolv.gai_error = ret;
    if (ret == 0) {
        args->socks->origin_resolution = res;
        args->socks->current_resolution = res;
    }

    (void) selector_notify_block(args->selector, args->client_fd);
    socks5_unref(args->socks);
    free(args);
    return NULL;
}

int
resolv_dispatch(struct selector_key *key, const char *name, const uint16_t port) {
    struct resolv_args *args = malloc(sizeof(*args));
    if (args == NULL) {
        return -1;
    }

    struct socks5 *s = key->data;
    memset(args, 0, sizeof(*args));
    args->selector  = key->s;
    args->client_fd = s->client_fd;
    args->socks     = s;
    snprintf(args->name, sizeof(args->name), "%s", name);
    snprintf(args->service, sizeof(args->service), "%u", (unsigned)ntohs(port));

    pthread_t tid;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        free(args);
        return -1;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        pthread_attr_destroy(&attr);
        free(args);
        return -1;
    }

    socks5_ref(s);
    if (pthread_create(&tid, &attr, resolv_blocking, args) != 0) {
        pthread_attr_destroy(&attr);
        socks5_unref(s);
        free(args);
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}
