/*
 * dbg_test.c — test de la política de activación del log de debug.
 * Compilar/correr con: make test
 */
#include <stdio.h>
#include <stdbool.h>
#include "dbg.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                              \
    checks++;                                              \
    if (cond) { printf("  ok  - %s\n", msg); }             \
    else      { printf("  FAIL- %s\n", msg); failures++; } \
} while (0)

int main(void) {
    CHECK(dbg_parse(NULL)  == false, "NULL  -> off (default)");
    CHECK(dbg_parse("")    == false, "''    -> off");
    CHECK(dbg_parse("0")   == false, "'0'   -> off");
    CHECK(dbg_parse("1")   == true,  "'1'   -> on");
    CHECK(dbg_parse("yes") == true,  "'yes' -> on");
    CHECK(dbg_parse("00")  == true,  "'00'  -> on (sólo '0' exacto apaga)");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
