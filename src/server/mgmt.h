#ifndef MGMT_H_TPE_SOCKS5
#define MGMT_H_TPE_SOCKS5

#include "selector.h"

/** configura la credencial de administrador del protocolo PMC. */
void mgmt_init(const char *admin_user, const char *admin_pass);

/** handler del socket pasivo PMC: acepta conexiones de management. */
void mgmt_passive_accept(struct selector_key *key);

#endif
