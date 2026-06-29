#ifndef MGMT_H_TPE_SOCKS5
#define MGMT_H_TPE_SOCKS5

#include "selector.h"

/** handler del socket pasivo PMC: acepta conexiones de management. */
void mgmt_passive_accept(struct selector_key *key);

#endif
