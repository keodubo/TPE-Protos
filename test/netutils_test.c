/*
 * netutils_test.c - tests blackbox de sockaddr_to_human().
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "netutils.h"

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

static void
test_sockaddr_to_human_ipv4(void) {
    char buff[50] = {0};

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(9090),
    };
    addr.sin_addr.s_addr = htonl(0x01020304);
    const struct sockaddr *x = (const struct sockaddr *) &addr;

    CHECK(strcmp(sockaddr_to_human(buff, sizeof(buff), x), "1.2.3.4:9090") == 0,
          "IPv4 completo -> 1.2.3.4:9090");
    CHECK(strcmp(sockaddr_to_human(buff, 5,  x), "1.2.") == 0,
          "IPv4 truncado con buffsize 5");
    CHECK(strcmp(sockaddr_to_human(buff, 8,  x), "1.2.3.4") == 0,
          "IPv4 truncado con buffsize 8");
    CHECK(strcmp(sockaddr_to_human(buff, 9,  x), "1.2.3.4:") == 0,
          "IPv4 truncado con buffsize 9");
    CHECK(strcmp(sockaddr_to_human(buff, 10, x), "1.2.3.4:9") == 0,
          "IPv4 truncado con buffsize 10");
    CHECK(strcmp(sockaddr_to_human(buff, 11, x), "1.2.3.4:90") == 0,
          "IPv4 truncado con buffsize 11");
    CHECK(strcmp(sockaddr_to_human(buff, 12, x), "1.2.3.4:909") == 0,
          "IPv4 truncado con buffsize 12");
    CHECK(strcmp(sockaddr_to_human(buff, 13, x), "1.2.3.4:9090") == 0,
          "IPv4 exacto con buffsize 13");
}

static void
test_sockaddr_to_human_ipv6(void) {
    char buff[50] = {0};

    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(9090),
    };
    uint8_t *d = (uint8_t *)&addr.sin6_addr;
    for (int i = 0; i < 16; i++) {
        d[i] = 0xFF;
    }

    const struct sockaddr *x = (const struct sockaddr *) &addr;
    CHECK(strcmp(sockaddr_to_human(buff, 10, x), "ffff:ffff") == 0,
          "IPv6 truncado con buffsize 10");
    CHECK(strcmp(sockaddr_to_human(buff, 39, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff") == 0,
          "IPv6 truncado con buffsize 39");
    CHECK(strcmp(sockaddr_to_human(buff, 40, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == 0,
          "IPv6 truncado con buffsize 40");
    CHECK(strcmp(sockaddr_to_human(buff, 41, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:") == 0,
          "IPv6 truncado con buffsize 41");
    CHECK(strcmp(sockaddr_to_human(buff, 42, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9") == 0,
          "IPv6 truncado con buffsize 42");
    CHECK(strcmp(sockaddr_to_human(buff, 43, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:90") == 0,
          "IPv6 truncado con buffsize 43");
    CHECK(strcmp(sockaddr_to_human(buff, 44, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:909") == 0,
          "IPv6 truncado con buffsize 44");
    CHECK(strcmp(sockaddr_to_human(buff, 45, x),
                 "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:9090") == 0,
          "IPv6 exacto con buffsize 45");
}

static void
test_sockaddr_to_human_zero_size_does_not_write_before_buffer(void) {
    char guard[3] = {'A', 'B', 'C'};
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(1),
    };
    addr.sin_addr.s_addr = htonl(0x7F000001);

    char *ret = (char *)sockaddr_to_human(&guard[1], 0,
                                          (const struct sockaddr *) &addr);
    CHECK(ret == &guard[1], "buffsize 0 devuelve el puntero recibido");
    CHECK(guard[0] == 'A' && guard[1] == 'B' && guard[2] == 'C',
          "buffsize 0 no escribe antes ni dentro del buffer");
}

static void
test_sockaddr_to_human_null_addr_truncates_with_nul(void) {
    char tiny[3] = {'X', 'X', 'X'};

    CHECK(strcmp(sockaddr_to_human(tiny, sizeof(tiny), NULL), "nu") == 0,
          "addr NULL truncado queda NUL-terminado");
    CHECK(tiny[2] == '\0', "addr NULL escribe terminador dentro del buffer");
}

int
main(void) {
    test_sockaddr_to_human_ipv4();
    test_sockaddr_to_human_ipv6();
    test_sockaddr_to_human_zero_size_does_not_write_before_buffer();
    test_sockaddr_to_human_null_addr_truncates_with_nul();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
