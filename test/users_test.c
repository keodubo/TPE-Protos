/*
 * users_test.c — tests blackbox de la tabla de usuarios del proxy.
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdio.h>
#include <stdbool.h>
#include "users.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

int main(void) {
    /* --- 1: alta + validación exacta --- */
    users_reset();
    CHECK(users_add("user", "pass"), "1: alta de user:pass");
    CHECK(users_count() == 1, "1: count = 1");
    CHECK(users_validate("user", "pass"), "1: valida credencial correcta");
    CHECK(users_validate_len("user", 4, "pass", 4),
          "1: valida credencial length-aware correcta");

    const char name_with_nul[] = {'u','s','e','r','\0','x'};
    const char pass_with_nul[] = {'p','a','s','s','\0','x'};
    CHECK(!users_validate_len(name_with_nul, sizeof(name_with_nul), "pass", 4),
          "1: rechaza nombre con NUL embebido");
    CHECK(!users_validate_len("user", 4, pass_with_nul, sizeof(pass_with_nul)),
          "1: rechaza pass con NUL embebido");

    /* --- 2: contraseña incorrecta / usuario inexistente --- */
    CHECK(!users_validate("user", "WRONG"), "2: rechaza pass incorrecta");
    CHECK(!users_validate("nope", "pass"),  "2: rechaza usuario inexistente");

    /* --- 3: case-sensitive --- */
    users_reset();
    users_add("User", "Pass");
    CHECK(!users_validate("user", "Pass"), "3: nombre case-sensitive");
    CHECK(!users_validate("User", "pass"), "3: pass case-sensitive");
    CHECK(users_validate("User", "Pass"),  "3: match exacto case-sensitive");

    /* --- 4: credenciales vacías rechazadas (D7.7) --- */
    users_reset();
    CHECK(!users_add("", "pass"),   "4: no agrega nombre vacío");
    CHECK(!users_add("user", ""),   "4: no agrega pass vacía");
    CHECK(users_count() == 0,       "4: tabla vacía tras altas inválidas");
    users_add("user", "pass");
    CHECK(!users_validate("", ""),     "4: rechaza login vacío");
    CHECK(!users_validate("user", ""), "4: rechaza pass vacía en login");

    /* --- 5: duplicados --- */
    users_reset();
    CHECK(users_add("u", "p1"),  "5: primer alta ok");
    CHECK(!users_add("u", "p2"), "5: rechaza nombre duplicado");
    CHECK(users_count() == 1,    "5: count sigue en 1");

    /* --- 6: capacidad --- */
    users_reset();
    bool all_ok = true;
    char nm[8];
    for (int i = 0; i < USERS_MAX; i++) {
        nm[0] = (char)('a' + i); nm[1] = '\0';
        if (!users_add(nm, "p")) all_ok = false;
    }
    CHECK(all_ok && users_count() == USERS_MAX, "6: entran USERS_MAX usuarios");
    CHECK(!users_add("Z", "p"), "6: rechaza al pasar la capacidad");

    /* --- 7: NULL no crashea --- */
    users_reset();
    CHECK(!users_add(NULL, "p"),      "7: add(NULL, p) -> false");
    CHECK(!users_add("u", NULL),      "7: add(u, NULL) -> false");
    CHECK(!users_validate(NULL, "p"), "7: validate(NULL, p) -> false");
    CHECK(!users_validate("u", NULL), "7: validate(u, NULL) -> false");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
