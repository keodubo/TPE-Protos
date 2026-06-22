/**
 * client.c — Cliente del protocolo de monitoreo/configuración del TPE.
 *
 * STUB (MILESTONE M7). Por ahora solo imprime el uso previsto.
 *
 * Cuando se implemente, este cliente:
 *   - usa I/O BLOQUEANTE (la consigna lo permite por su simpleza),
 *   - habla el protocolo de TEXTO definido en docs/mgmt-protocol-rfc.md,
 *   - NO es netcat: abstrae el protocolo en subcomandos cómodos.
 *
 * Uso previsto:
 *   client [-L <addr>] [-P <port>] [-u <admin>] [-w <pass>] <comando> [args...]
 *     add-user <name> <pass>
 *     del-user <name>
 *     list-users
 *     metrics
 *     get-config <key>
 *     set-config <key> <value>
 *   Ej: client add-user pablito pass1234
 */
#include <stdio.h>

int
main(const int argc, const char **argv) {
    (void) argc;
    fprintf(stderr,
            "client: cliente de monitoreo del TPE SOCKS5 (TODO: implementar en M7)\n"
            "Uso previsto: %s [-L addr] [-P port] <comando> [args...]\n"
            "  Ej: %s add-user pablito pass1234\n",
            argv[0], argv[0]);
    return 0;
}
