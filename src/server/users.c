/*
 * users.c — tabla de usuarios del proxy SOCKS5 (almacenamiento file-scope).
 * Fuente de verdad única para la validación RFC1929 (D7.2).
 */
#include "users.h"
#include <string.h>

#define USERS_FIELD_MAX 255   /* límite de RFC1929 (ULEN/PLEN en 1 byte) */

struct user_entry {
    char name[USERS_FIELD_MAX + 1];
    char pass[USERS_FIELD_MAX + 1];
    bool used;
};

static struct user_entry table[USERS_MAX];
static size_t            count = 0;

void
users_reset(void) {
    memset(table, 0, sizeof(table));
    count = 0;
}

/** un campo válido: no NULL, no vacío, y entra en el límite del cable (D7.7) */
static bool
valid_field(const char *s) {
    if (s == NULL) {
        return false;
    }
    const size_t n = strlen(s);
    return n > 0 && n <= USERS_FIELD_MAX;
}

bool
users_add(const char *name, const char *pass) {
    if (!valid_field(name) || !valid_field(pass)) {
        return false;
    }
    if (count >= USERS_MAX) {
        return false;
    }
    for (size_t i = 0; i < USERS_MAX; i++) {              /* duplicado por nombre */
        if (table[i].used && strcmp(table[i].name, name) == 0) {
            return false;
        }
    }
    for (size_t i = 0; i < USERS_MAX; i++) {              /* primer slot libre */
        if (!table[i].used) {
            memcpy(table[i].name, name, strlen(name) + 1);
            memcpy(table[i].pass, pass, strlen(pass) + 1);
            table[i].used = true;
            count++;
            return true;
        }
    }
    return false;
}

bool
users_validate(const char *name, const char *pass) {
    if (!valid_field(name) || !valid_field(pass)) {       /* vacío/NULL => rechazo (D7.7) */
        return false;
    }
    for (size_t i = 0; i < USERS_MAX; i++) {
        if (table[i].used
                && strcmp(table[i].name, name) == 0
                && strcmp(table[i].pass, pass) == 0) {
            return true;
        }
    }
    return false;
}

size_t
users_count(void) {
    return count;
}
