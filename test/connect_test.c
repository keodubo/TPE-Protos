/*
 * connect_test.c - tests blackbox del mapeo errno -> REP SOCKS5.
 * Harness plano en C (sin libcheck). Correr con: make test
 *
 * Solo ejercita request_connect_errno_rep(), que es logica pura (errno->REP).
 * No invoca request_connect_addr() para no depender de I/O real ni del selector.
 */
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>

#include "connect.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

int
main(void) {
    /* errores de red/host/conexion mapeados explicitamente */
    CHECK(request_connect_errno_rep(ENETUNREACH) == REQUEST_REP_NETWORK_UNREACHABLE,
          "ENETUNREACH -> NETWORK_UNREACHABLE (0x03)");
    CHECK(request_connect_errno_rep(ENETUNREACH) == 0x03,
          "ENETUNREACH -> 0x03");

    CHECK(request_connect_errno_rep(EHOSTUNREACH) == REQUEST_REP_HOST_UNREACHABLE,
          "EHOSTUNREACH -> HOST_UNREACHABLE (0x04)");
    CHECK(request_connect_errno_rep(EHOSTUNREACH) == 0x04,
          "EHOSTUNREACH -> 0x04");
    CHECK(request_connect_errno_rep(ETIMEDOUT) == REQUEST_REP_HOST_UNREACHABLE,
          "ETIMEDOUT -> HOST_UNREACHABLE (0x04)");
    CHECK(request_connect_errno_rep(ETIMEDOUT) == 0x04,
          "ETIMEDOUT -> 0x04");

    CHECK(request_connect_errno_rep(ECONNREFUSED) == REQUEST_REP_CONNECTION_REFUSED,
          "ECONNREFUSED -> CONNECTION_REFUSED (0x05)");
    CHECK(request_connect_errno_rep(ECONNREFUSED) == 0x05,
          "ECONNREFUSED -> 0x05");

    /* nuevos mapeos (f28): firewall local y red caida */
    CHECK(request_connect_errno_rep(EACCES) == REQUEST_REP_CONNECTION_NOT_ALLOWED,
          "EACCES -> CONNECTION_NOT_ALLOWED (0x02)");
    CHECK(request_connect_errno_rep(EACCES) == 0x02,
          "EACCES -> 0x02");
    CHECK(request_connect_errno_rep(EPERM) == REQUEST_REP_CONNECTION_NOT_ALLOWED,
          "EPERM -> CONNECTION_NOT_ALLOWED (0x02)");
    CHECK(request_connect_errno_rep(EPERM) == 0x02,
          "EPERM -> 0x02");
    CHECK(request_connect_errno_rep(ENETDOWN) == REQUEST_REP_NETWORK_UNREACHABLE,
          "ENETDOWN -> NETWORK_UNREACHABLE (0x03)");
    CHECK(request_connect_errno_rep(ENETDOWN) == 0x03,
          "ENETDOWN -> 0x03");

    /* default consciente: un errno no mapeado cae a fallo general */
    CHECK(request_connect_errno_rep(EINVAL) == REQUEST_REP_GENERAL_FAILURE,
          "EINVAL (no mapeado) -> GENERAL_FAILURE (0x01)");
    CHECK(request_connect_errno_rep(EINVAL) == 0x01,
          "EINVAL (no mapeado) -> 0x01");
    CHECK(request_connect_errno_rep(0) == REQUEST_REP_GENERAL_FAILURE,
          "errno 0 (no mapeado) -> GENERAL_FAILURE (0x01)");

    /* errores DNS/getaddrinfo -> REP */
    CHECK(request_resolve_error_rep(EAI_NONAME, 0) == REQUEST_REP_HOST_UNREACHABLE,
          "EAI_NONAME -> HOST_UNREACHABLE (0x04)");
    CHECK(request_resolve_error_rep(EAI_AGAIN, 0) == REQUEST_REP_HOST_UNREACHABLE,
          "EAI_AGAIN -> HOST_UNREACHABLE (0x04)");
    CHECK(request_resolve_error_rep(EAI_MEMORY, 0) == REQUEST_REP_GENERAL_FAILURE,
          "EAI_MEMORY -> GENERAL_FAILURE (0x01)");
    CHECK(request_resolve_error_rep(EAI_SYSTEM, ENETDOWN)
              == REQUEST_REP_NETWORK_UNREACHABLE,
          "EAI_SYSTEM + ENETDOWN -> NETWORK_UNREACHABLE (0x03)");
    CHECK(request_resolve_error_rep(EAI_SYSTEM, EACCES)
              == REQUEST_REP_CONNECTION_NOT_ALLOWED,
          "EAI_SYSTEM + EACCES -> CONNECTION_NOT_ALLOWED (0x02)");
    CHECK(request_resolve_error_rep(0, 0) == REQUEST_REP_SUCCEEDED,
          "gai 0 -> SUCCEEDED (0x00)");

    printf("\nconnect_test: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
