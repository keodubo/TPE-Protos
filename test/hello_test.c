/*
 * hello_test.c — tests blackbox del parser/serializador HELLO (RFC1928 §3).
 *
 * Harness plano en C (sin libcheck) para que corra con gcc/clang en macOS
 * y en pampero sin dependencias. Compilar con:
 *   make test         (target del Makefile)
 * o a mano:
 *   cc -std=c11 -Isrc/shared -Isrc/server test/hello_test.c \
 *      src/server/hello.c src/shared/buffer.c -o /tmp/hello_test && /tmp/hello_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "hello.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

/* callback de prueba: registra cada método ofrecido y aplica la política A
 * (elegir USERPASS si se ofrece; default = NO_ACCEPTABLE). */
struct rec { uint8_t methods[260]; int count; uint8_t selected; };

static void on_method(struct hello_parser *p, uint8_t m) {
    struct rec *r = p->data;
    if (r->count < (int)sizeof(r->methods)) r->methods[r->count] = m;
    r->count++;
    if (m == SOCKS_HELLO_USERPASS) r->selected = SOCKS_HELLO_USERPASS;
}

/* helper: arma un buffer con los bytes dados */
static void fill(buffer *b, const uint8_t *bytes, size_t n) {
    size_t cap;
    uint8_t *p = buffer_write_ptr(b, &cap);
    memcpy(p, bytes, n);
    buffer_write_adv(b, n);
}

static struct hello_parser mk(struct rec *r) {
    struct hello_parser p;
    hello_parser_init(&p);
    p.on_authentication_method = on_method;
    p.data = r;
    return p;
}

int main(void) {
    /* --- 1: saludo simple, ofrece USERPASS --- */
    {
        struct rec r = { .selected = SOCKS_HELLO_NO_ACCEPTABLE_METHODS };
        struct hello_parser p = mk(&r);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t greet[] = { 0x05, 0x01, 0x02 };
        fill(&b, greet, sizeof(greet));
        bool err = false;
        enum hello_state st = hello_consume(&b, &p, &err);
        CHECK(!err, "1: sin error");
        CHECK(hello_is_done(st, &err), "1: parser terminó");
        CHECK(r.count == 1, "1: un método ofrecido");
        CHECK(r.methods[0] == 0x02, "1: método ofrecido = 0x02");
        CHECK(r.selected == SOCKS_HELLO_USERPASS, "1: selecciona USERPASS");
    }

    /* --- 2: lecturas PARCIALES (los 3 bytes llegan de a uno) --- */
    {
        struct rec r = { .selected = SOCKS_HELLO_NO_ACCEPTABLE_METHODS };
        struct hello_parser p = mk(&r);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        bool err = false;
        uint8_t b0[] = {0x05}, b1[] = {0x01}, b2[] = {0x02};
        fill(&b, b0, 1); hello_consume(&b, &p, &err);
        fill(&b, b1, 1); hello_consume(&b, &p, &err);
        fill(&b, b2, 1); enum hello_state st = hello_consume(&b, &p, &err);
        CHECK(!err && hello_is_done(st, &err), "2: termina con bytes parciales");
        CHECK(r.selected == SOCKS_HELLO_USERPASS, "2: selecciona USERPASS");
    }

    /* --- 3: varios métodos ofrecidos --- */
    {
        struct rec r = { .selected = SOCKS_HELLO_NO_ACCEPTABLE_METHODS };
        struct hello_parser p = mk(&r);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t greet[] = { 0x05, 0x03, 0x00, 0x01, 0x02 };
        fill(&b, greet, sizeof(greet));
        bool err = false;
        enum hello_state st = hello_consume(&b, &p, &err);
        CHECK(hello_is_done(st, &err) && !err, "3: termina");
        CHECK(r.count == 3, "3: tres métodos ofrecidos");
        CHECK(r.selected == SOCKS_HELLO_USERPASS, "3: elige USERPASS entre varios");
    }

    /* --- 4: solo no-auth ofrecido => no se selecciona USERPASS --- */
    {
        struct rec r = { .selected = SOCKS_HELLO_NO_ACCEPTABLE_METHODS };
        struct hello_parser p = mk(&r);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t greet[] = { 0x05, 0x01, 0x00 };
        fill(&b, greet, sizeof(greet));
        bool err = false;
        enum hello_state st = hello_consume(&b, &p, &err);
        CHECK(hello_is_done(st, &err) && !err, "4: termina");
        CHECK(r.selected == SOCKS_HELLO_NO_ACCEPTABLE_METHODS,
              "4: sin USERPASS queda NO_ACCEPTABLE");
    }

    /* --- 5: versión inválida => error --- */
    {
        struct rec r = { .selected = SOCKS_HELLO_NO_ACCEPTABLE_METHODS };
        struct hello_parser p = mk(&r);
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        uint8_t greet[] = { 0x04, 0x01, 0x00 };
        fill(&b, greet, sizeof(greet));
        bool err = false;
        hello_consume(&b, &p, &err);
        CHECK(err, "5: VER != 0x05 marca error");
    }

    /* --- 6: serialización de la respuesta del servidor --- */
    {
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        int n = hello_marshall(&b, SOCKS_HELLO_USERPASS);
        size_t cnt; uint8_t *p = buffer_read_ptr(&b, &cnt);
        CHECK(n == 2 && cnt == 2, "6: marshall escribe 2 bytes");
        CHECK(p[0] == 0x05 && p[1] == 0x02, "6: respuesta = 05 02");
    }
    {
        uint8_t raw[16]; buffer b; buffer_init(&b, sizeof(raw), raw);
        hello_marshall(&b, SOCKS_HELLO_NO_ACCEPTABLE_METHODS);
        size_t cnt; uint8_t *p = buffer_read_ptr(&b, &cnt);
        CHECK(cnt == 2 && p[0] == 0x05 && p[1] == 0xFF, "6: respuesta rechazo = 05 FF");
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
