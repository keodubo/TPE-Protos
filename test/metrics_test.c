/*
 * metrics_test.c - tests blackbox de los contadores volatiles de M6.
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdio.h>

#include "metrics.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

int
main(void) {
    const struct socks_metrics *m;

    metrics_init();
    m = metrics_get();
    CHECK(m->historic_connections == 0, "1: init deja historicas en 0");
    CHECK(m->current_connections == 0,  "1: init deja concurrentes en 0");
    CHECK(m->failed_connections == 0,   "1: init deja fallidas en 0");
    CHECK(m->current_users == 0,        "1: init deja usuarios actuales en 0");
    CHECK(m->bytes_transferred == 0,    "1: init deja bytes en 0");

    metrics_connection_opened();
    metrics_connection_opened();
    metrics_connection_opened();
    m = metrics_get();
    CHECK(m->historic_connections == 3, "2: opened incrementa historicas");
    CHECK(m->current_connections == 3,  "2: opened incrementa concurrentes");

    metrics_connection_closed();
    metrics_connection_closed();
    m = metrics_get();
    CHECK(m->historic_connections == 3, "3: closed no cambia historicas");
    CHECK(m->current_connections == 1,  "3: closed decrementa concurrentes");

    metrics_connection_closed();
    metrics_connection_closed();
    m = metrics_get();
    CHECK(m->current_connections == 0,  "4: closed no baja de 0");

    metrics_connection_failed();
    metrics_connection_failed();
    metrics_add_bytes(100);
    metrics_add_bytes(50);
    m = metrics_get();
    CHECK(m->failed_connections == 2,   "5: failed incrementa fallidas");
    CHECK(m->bytes_transferred == 150,  "5: add_bytes suma bytes reales");

    metrics_init();
    m = metrics_get();
    CHECK(m->historic_connections == 0, "6: init reinicia historicas");
    CHECK(m->current_connections == 0,  "6: init reinicia concurrentes");
    CHECK(m->failed_connections == 0,   "6: init reinicia fallidas");
    CHECK(m->bytes_transferred == 0,    "6: init reinicia bytes");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
