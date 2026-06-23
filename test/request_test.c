/*
 * request_test.c - tests blackbox del parser/serializador REQUEST (RFC1928).
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "buffer.h"
#include "request.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

static void
fill(buffer *b, const uint8_t *bytes, size_t n) {
    size_t cap;
    uint8_t *p = buffer_write_ptr(b, &cap);
    (void)cap;
    memcpy(p, bytes, n);
    buffer_write_adv(b, (ssize_t)n);
}

static bool
port_has_bytes(uint16_t port, uint8_t high, uint8_t low) {
    uint8_t raw[2];
    memcpy(raw, &port, sizeof(raw));
    return raw[0] == high && raw[1] == low;
}

static bool
buffer_matches(buffer *b, const uint8_t *expected, size_t n) {
    size_t count;
    uint8_t *p = buffer_read_ptr(b, &count);
    return count == n && memcmp(p, expected, n) == 0;
}

int
main(void) {
    /* --- 1: request IPv4 valido CONNECT 192.0.2.10:8080 --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[32]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = {
            0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x1F, 0x90
        };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(!err, "1: sin error");
        CHECK(request_is_done(st, &err), "1: parser termino");
        CHECK(p.request.cmd == 0x01, "1: CMD = CONNECT");
        CHECK(p.request.atyp == 0x01, "1: ATYP = IPv4");
        CHECK(memcmp(p.request.dst_addr, (uint8_t[]){192, 0, 2, 10}, 4) == 0,
              "1: DST.ADDR preserva bytes IPv4");
        CHECK(port_has_bytes(p.request.dst_port, 0x1F, 0x90),
              "1: DST.PORT queda en network byte order");
        CHECK(request_state_rep(st) == 0x00, "1: REP success");
    }

    /* --- 2: request en fragmentos byte a byte --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[32]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = {
            0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x00, 0x50
        };
        bool err = false;
        enum request_state st = request_version;
        for (size_t i = 0; i < sizeof(req); i++) {
            fill(&b, &req[i], 1);
            st = request_consume(&b, &p, &err);
        }
        CHECK(!err && request_is_done(st, &err),
              "2: termina con bytes parciales");
        CHECK(memcmp(p.request.dst_addr, (uint8_t[]){203, 0, 113, 7}, 4) == 0,
              "2: DST.ADDR correcto");
        CHECK(port_has_bytes(p.request.dst_port, 0x00, 0x50),
              "2: puerto 80 en network byte order");
    }

    /* --- 3: CMD no soportado -> REP 0x07 --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80 };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(err && request_is_done(st, &err), "3: CMD=0x02 marca error");
        CHECK(request_state_rep(st) == 0x07, "3: REP command not supported");
    }

    /* --- 4: ATYP no soportado -> REP 0x08 --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x05, 0x01, 0x00, 0x03, 0x0B };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(err && request_is_done(st, &err), "4: ATYP=0x03 marca error");
        CHECK(request_state_rep(st) == 0x08, "4: REP address type not supported");
    }

    /* --- 5: VER invalida -> error general 0x01 --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x04, 0x01, 0x00, 0x01 };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(err && request_is_done(st, &err), "5: VER invalida marca error");
        CHECK(request_state_rep(st) == 0x01, "5: REP general failure");
    }

    /* --- 6: RSV invalido -> error general 0x01 --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x05, 0x01, 0x01, 0x01 };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(err && request_is_done(st, &err), "6: RSV invalido marca error");
        CHECK(request_state_rep(st) == 0x01, "6: REP general failure");
    }

    /* --- 7: marshall success con BND.ADDR/BND.PORT reales --- */
    {
        struct sockaddr_in bound;
        memset(&bound, 0, sizeof(bound));
        bound.sin_family = AF_INET;
        memcpy(&bound.sin_addr.s_addr, (uint8_t[]){127, 0, 0, 1}, 4);
        memcpy(&bound.sin_port, (uint8_t[]){0x1F, 0x90}, 2);

        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        int n = request_marshall(&b, 0x00, &bound);
        uint8_t expected[] = {
            0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90
        };
        CHECK(n == 10, "7: marshall escribe 10 bytes");
        CHECK(buffer_matches(&b, expected, sizeof(expected)),
              "7: respuesta success exacta");
    }

    /* --- 8: marshall error con NULL -> 0.0.0.0:0 --- */
    {
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        int n = request_marshall(&b, 0x01, NULL);
        uint8_t expected[] = {
            0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0
        };
        CHECK(n == 10, "8: marshall error escribe 10 bytes");
        CHECK(buffer_matches(&b, expected, sizeof(expected)),
              "8: error usa 0.0.0.0:0");
    }

    /* --- 9: tras terminar, request_consume NO consume bytes extra --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[32]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = {
            0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB, 0xAB
        };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(request_is_done(st, &err) && !err, "9: primer consume termina");
        CHECK(buffer_can_read(&b), "9: el byte extra sigue en el buffer");
        enum request_state st2 = request_consume(&b, &p, &err);
        CHECK(request_is_done(st2, &err) && buffer_can_read(&b),
              "9: segundo consume NO toca el extra");
        CHECK(buffer_read(&b) == 0xAB, "9: byte preservado = 0xAB");
    }

    /* --- 10: tras ERROR final, los bytes extra siguen en el buffer --- */
    {
        struct request_parser p; request_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        /* ATYP=0x03 fuerza error en el byte de ATYP (el ultimo antes del
         * extra); el consume corta ahi, dejando solo 0xAB sin consumir. */
        uint8_t req[] = { 0x05, 0x01, 0x00, 0x03, 0xAB };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum request_state st = request_consume(&b, &p, &err);
        CHECK(err && request_is_done(st, &err), "10: ATYP=0x03 marca error final");
        CHECK(request_state_rep(st) == 0x08, "10: REP address type not supported");
        CHECK(buffer_can_read(&b), "10: el byte extra sigue en el buffer tras error");
        CHECK(buffer_read(&b) == 0xAB, "10: byte preservado tras error = 0xAB");
    }

    /* --- 11: marshall sin espacio (<10 bytes libres) devuelve -1 --- */
    {
        uint8_t raw[9]; buffer b; buffer_init(&b, sizeof(raw), raw);
        int n = request_marshall(&b, 0x00, NULL);
        CHECK(n == -1, "11: marshall devuelve -1 sin espacio (<10 libres)");
        CHECK(!buffer_can_read(&b), "11: no escribio bytes en el buffer");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
