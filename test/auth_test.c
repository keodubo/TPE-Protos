/*
 * auth_test.c — tests blackbox del parser/serializador AUTH (RFC1929).
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "auth.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

static void fill(buffer *b, const uint8_t *bytes, size_t n) {
    size_t cap;
    uint8_t *p = buffer_write_ptr(b, &cap);
    memcpy(p, bytes, n);
    buffer_write_adv(b, n);
}

int main(void) {
    /* --- 1: request completo VER ULEN "user" PLEN "pass" --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[64]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x01, 0x04,'u','s','e','r', 0x04,'p','a','s','s' };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum auth_state st = auth_consume(&b, &p, &err);
        CHECK(!err, "1: sin error");
        CHECK(auth_is_done(st, &err), "1: parser terminó");
        CHECK(strcmp(p.uname, "user") == 0, "1: uname = user");
        CHECK(strcmp(p.passwd, "pass") == 0, "1: passwd = pass");
    }

    /* --- 2: lecturas parciales (byte a byte) --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[64]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x01, 0x02,'a','b', 0x03,'x','y','z' };
        bool err = false; enum auth_state st = auth_version;
        for (size_t i = 0; i < sizeof(req); i++) {
            fill(&b, &req[i], 1);
            st = auth_consume(&b, &p, &err);
        }
        CHECK(!err && auth_is_done(st, &err), "2: termina con bytes parciales");
        CHECK(strcmp(p.uname, "ab") == 0 && strcmp(p.passwd, "xyz") == 0,
              "2: campos correctos byte a byte");
    }

    /* --- 3: pipelined — request + byte extra; no consumir el extra --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[64]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x01, 0x01,'u', 0x01,'p', 0xAB };  /* 0xAB sobra (request M3) */
        fill(&b, req, sizeof(req));
        bool err = false;
        enum auth_state st = auth_consume(&b, &p, &err);
        CHECK(auth_is_done(st, &err) && !err, "3: termina");
        CHECK(buffer_can_read(&b), "3: el byte extra sigue en el buffer");
        enum auth_state st2 = auth_consume(&b, &p, &err);   /* ya done */
        CHECK(auth_is_done(st2, &err) && buffer_can_read(&b),
              "3: segundo consume NO toca el byte extra");
        CHECK(buffer_read(&b) == 0xAB, "3: el byte preservado es 0xAB");
    }

    /* --- 4: versión inválida (VER != 0x01) --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x05, 0x01,'u', 0x01,'p' };
        fill(&b, req, sizeof(req));
        bool err = false;
        auth_consume(&b, &p, &err);
        CHECK(err, "4: VER != 0x01 marca error");
    }

    /* --- 5: ULEN=0 (usuario vacío) — el parser produce "" --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x01, 0x00, 0x02,'p','w' };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum auth_state st = auth_consume(&b, &p, &err);
        CHECK(!err && auth_is_done(st, &err), "5: ULEN=0 termina");
        CHECK(p.uname[0] == '\0' && strcmp(p.passwd, "pw") == 0,
              "5: uname vacío, passwd = pw");
    }

    /* --- 6: PLEN=0 (contraseña vacía) --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[] = { 0x01, 0x01,'u', 0x00 };
        fill(&b, req, sizeof(req));
        bool err = false;
        enum auth_state st = auth_consume(&b, &p, &err);
        CHECK(!err && auth_is_done(st, &err), "6: PLEN=0 termina");
        CHECK(strcmp(p.uname, "u") == 0 && p.passwd[0] == '\0',
              "6: uname = u, passwd vacío");
    }

    /* --- 7: longitudes máximas (255 + 255), sin overflow --- */
    {
        struct auth_parser p; auth_parser_init(&p);
        uint8_t raw[600]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t req[1 + 1 + 255 + 1 + 255];
        size_t k = 0;
        req[k++] = 0x01; req[k++] = 0xFF;
        for (int i = 0; i < 255; i++) req[k++] = 'A';
        req[k++] = 0xFF;
        for (int i = 0; i < 255; i++) req[k++] = 'B';
        fill(&b, req, k);
        bool err = false;
        enum auth_state st = auth_consume(&b, &p, &err);
        CHECK(!err && auth_is_done(st, &err), "7: 255+255 termina");
        CHECK(strlen(p.uname) == 255 && strlen(p.passwd) == 255,
              "7: ambos campos de 255 y NUL-terminados");
    }

    /* --- 8: marshall de la respuesta --- */
    {
        uint8_t raw[8]; buffer b; buffer_init(&b, sizeof(raw), raw);
        int n = auth_marshall(&b, AUTH_STATUS_OK);
        size_t cnt; uint8_t *p = buffer_read_ptr(&b, &cnt);
        CHECK(n == 2 && cnt == 2 && p[0] == 0x01 && p[1] == 0x00, "8: OK -> 01 00");
    }
    {
        uint8_t raw[8]; buffer b; buffer_init(&b, sizeof(raw), raw);
        auth_marshall(&b, AUTH_STATUS_FAIL);
        size_t cnt; uint8_t *p = buffer_read_ptr(&b, &cnt);
        CHECK(cnt == 2 && p[0] == 0x01 && p[1] == 0x01, "8: FAIL -> 01 01");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
