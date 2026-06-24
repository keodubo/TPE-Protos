#ifndef RESOLV_H_TPE_SOCKS5
#define RESOLV_H_TPE_SOCKS5

#include <stdint.h>

#include "selector.h"

int resolv_dispatch(struct selector_key *key, const char *name, uint16_t port);

#endif
