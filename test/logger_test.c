/*
 * logger_test.c - tests blackbox del access-log de M6.
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "logger.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

static bool
timestamp_shape_ok(const char *s) {
    const char *tab = strchr(s, '\t');
    if (tab == NULL || (tab - s) != 20) {
        return false;
    }
    return s[4] == '-' && s[7] == '-' && s[10] == 'T'
        && s[13] == ':' && s[16] == ':' && s[19] == 'Z';
}

int
main(void) {
    char  *out = NULL;
    size_t out_len = 0;
    FILE  *mem = open_memstream(&out, &out_len);
    if (mem == NULL) {
        perror("open_memstream");
        return 2;
    }

    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_port = htons(53122);
    inet_pton(AF_INET, "127.0.0.1", &client.sin_addr);

    logger_init(mem);
    logger_log_access("user1", (const struct sockaddr *) &client,
                      "example.com", 80, ACCESS_OK);
    fflush(mem);

    CHECK(out_len > 0, "1: logger escribe una línea");
    CHECK(timestamp_shape_ok(out), "1: timestamp ISO-8601 UTC");
    CHECK(strstr(out, "\tuser1\t127.0.0.1:53122\texample.com:80\tOK\n") != NULL,
          "1: campos OK separados por tabs");

    free(out);
    out = NULL;
    out_len = 0;
    fclose(mem);

    mem = open_memstream(&out, &out_len);
    if (mem == NULL) {
        perror("open_memstream");
        return 2;
    }
    logger_init(mem);
    logger_log_access("", (const struct sockaddr *) &client,
                      "blocked.local", 443, ACCESS_FAIL);
    fflush(mem);

    CHECK(strstr(out, "\t-\t127.0.0.1:53122\tblocked.local:443\tFAIL\n") != NULL,
          "2: usuario vacío se imprime como '-' y FAIL");

    fclose(mem);
    free(out);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
