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
    size_t name_len;
    size_t pass_len;
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
valid_field_len(const char *s, const size_t n) {
    if (s == NULL) {
        return false;
    }
    return n > 0 && n <= USERS_FIELD_MAX;
}

static bool
valid_field(const char *s, size_t *len) {
    if (s == NULL) {
        return false;
    }
    const size_t n = strlen(s);
    if (!valid_field_len(s, n)) {
        return false;
    }
    if (len != NULL) {
        *len = n;
    }
    return true;
}

bool
users_add(const char *name, const char *pass) {
    size_t name_len = 0;
    size_t pass_len = 0;
    if (!valid_field(name, &name_len) || !valid_field(pass, &pass_len)) {
        return false;
    }
    if (count >= USERS_MAX) {
        return false;
    }
    for (size_t i = 0; i < USERS_MAX; i++) {              /* duplicado por nombre */
        if (table[i].used
                && table[i].name_len == name_len
                && memcmp(table[i].name, name, name_len) == 0) {
            return false;
        }
    }
    for (size_t i = 0; i < USERS_MAX; i++) {              /* primer slot libre */
        if (!table[i].used) {
            memcpy(table[i].name, name, name_len);
            table[i].name[name_len] = '\0';
            memcpy(table[i].pass, pass, pass_len);
            table[i].pass[pass_len] = '\0';
            table[i].name_len = name_len;
            table[i].pass_len = pass_len;
            table[i].used = true;
            count++;
            return true;
        }
    }
    return false;
}

bool
users_validate(const char *name, const char *pass) {
    if (name == NULL || pass == NULL) {
        return false;
    }
    return users_validate_len(name, strlen(name), pass, strlen(pass));
}

bool
users_validate_len(const char *name, const size_t name_len,
                   const char *pass, const size_t pass_len) {
    if (!valid_field_len(name, name_len) || !valid_field_len(pass, pass_len)) {
        return false;
    }
    for (size_t i = 0; i < USERS_MAX; i++) {
        if (table[i].used
                && table[i].name_len == name_len
                && table[i].pass_len == pass_len
                && memcmp(table[i].name, name, name_len) == 0
                && memcmp(table[i].pass, pass, pass_len) == 0) {
            return true;
        }
    }
    return false;
}

size_t
users_count(void) {
    return count;
}
