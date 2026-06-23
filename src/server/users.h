#ifndef USERS_H_TPE_SOCKS5
#define USERS_H_TPE_SOCKS5

/*
 * users.h — tabla de usuarios del proxy SOCKS5 (los del `-u name:pass`).
 *
 * Fuente de verdad única para la validación RFC1929 (D7.2). Desacoplada de
 * cómo se cargan: en M2 la puebla main() desde args; en M7 la extenderá el
 * protocolo de gestión (ADD/DEL/LIST-USER) sin tocar el call-site de auth.
 * NO es la credencial de admin del protocolo de monitoreo (esa es otra, D2).
 */
#include <stdbool.h>
#include <stddef.h>

#define USERS_MAX 10   /* igual que MAX_USERS en args.h */

/** vacía la tabla (para reinicio/tests) */
void users_reset(void);

/**
 * Agrega un usuario. Devuelve false si: name/pass NULL o vacíos (D7.7),
 * nombre duplicado, o la tabla está llena.
 */
bool users_add(const char *name, const char *pass);

/**
 * true si (name, pass) coincide EXACTO (byte a byte, case-sensitive) con un
 * usuario cargado. Credenciales vacías => false (D7.7).
 */
bool users_validate(const char *name, const char *pass);

/**
 * Variante para RFC1929: compara usando las longitudes ULEN/PLEN recibidas por
 * el cable, por lo que bytes NUL embebidos no pueden autenticar como prefijo.
 */
bool users_validate_len(const char *name, size_t name_len,
                        const char *pass, size_t pass_len);

/** cantidad de usuarios cargados */
size_t users_count(void);

#endif
