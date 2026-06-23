#ifndef DBG_H_TPE_SOCKS5
#define DBG_H_TPE_SOCKS5

#include <stdio.h>
#include <stdbool.h>

/**
 * Log de debug para QA/desarrollo. Va a stderr y está APAGADO por defecto;
 * se activa con la variable de entorno SOCKS5_DEBUG:
 *
 *   SOCKS5_DEBUG=1 ./bin/server -p 1080 -u user:pass
 *
 * No usa el flag -v (que en args.c imprime la versión). Apagado en producción
 * para no afectar las pruebas de estrés.
 */

/** política de activación a partir del valor de SOCKS5_DEBUG.
 *  OFF: NULL / "" / "0".  ON: cualquier otro valor. */
bool
dbg_parse(const char *env);

/** true si el log está activo (lee SOCKS5_DEBUG una vez y cachea). */
bool
dbg_enabled(void);

/** imprime una línea a stderr (con \n) sólo si el log está activo. */
#define DBG(...) do {                  \
    if (dbg_enabled()) {               \
        fprintf(stderr, __VA_ARGS__);  \
        fputc('\n', stderr);           \
    }                                  \
} while (0)

#endif
