#ifndef COPY_H_TPE_SOCKS5
#define COPY_H_TPE_SOCKS5

#include "buffer.h"
#include "selector.h"

struct copy {
    int                 *fd;
    buffer              *rb;
    buffer              *wb;
    fd_interest          duplex;
    struct copy         *other;
    struct selector_key  key;
};

void copy_init(unsigned state, struct selector_key *key);
unsigned copy_read(struct selector_key *key);
unsigned copy_write(struct selector_key *key);
selector_status copy_compute_interests(struct copy *c);

#endif
