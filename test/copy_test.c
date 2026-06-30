/*
 * copy_test.c - tests blackbox del relay COPY bidireccional (M4).
 *
 * Harness plano en C (sin libcheck). Correr con: make test
 *
 * Estrategia (behavior-only): se arma un selector real y un par de
 * socketpair() en O_NONBLOCK; sobre ellos se construyen structs `copy` con
 * buffers controlados. El interés que `copy_compute_interests` deja en el
 * selector NO tiene getter público, así que se observa de forma blackbox:
 *   - un socketpair vacío es SIEMPRE escribible -> si quedó OP_WRITE, dispara
 *     el handler de write;
 *   - se hace legible escribiendo desde el otro extremo -> si quedó OP_READ,
 *     dispara el handler de read;
 *   - si quedó OP_NOOP, no dispara ninguno.
 * Para copy_next_state -> DONE y el half-close se maneja copy_read/copy_write
 * con un struct socks5 mínimo armado a mano (sin pool ni socks5nio.c).
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>

#include "buffer.h"
#include "selector.h"
#include "copy.h"
#include "socks5.h"
#include "metrics.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                \
    else      { printf("  FAIL- %s\n", msg); failures++; }    \
} while (0)

/* ---- observación blackbox del interés vía el selector real ---- */

static bool read_fired;
static bool write_fired;

static void
obs_read(struct selector_key *key) {
    (void) key;
    read_fired = true;
}

static void
obs_write(struct selector_key *key) {
    (void) key;
    write_fired = true;
}

static const struct fd_handler OBS_HANDLER = {
    .handle_read  = obs_read,
    .handle_write = obs_write,
    .handle_block = NULL,
    .handle_close = NULL,
};

static void
set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Corre una iteración del selector y reporta qué interés quedó activo.
 * `peer` es el otro extremo del socketpair de `fd`: si se le escribe, `fd`
 * pasa a legible y eso revela un eventual OP_READ. */
static void
observe_interest(fd_selector s, int peer, bool *got_read, bool *got_write) {
    read_fired = write_fired = false;
    /* hacer legible el fd observado para revelar OP_READ */
    (void) write(peer, "x", 1);
    /* drenar cualquier dato previo del fd no afecta: el handler sólo marca */
    selector_select(s);
    *got_read  = read_fired;
    *got_write = write_fired;
}

int
main(void) {
    signal(SIGPIPE, SIG_IGN);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 },
    };
    if (selector_init(&conf) != 0) {
        fprintf(stderr, "selector_init falló\n");
        return 2;
    }

    /* ===================================================================
     * Grupo 1: copy_compute_interests sobre un solo `copy`
     * =================================================================== */

    /* --- 1: duplex READ|WRITE, rb escribible y wb con datos -> OP_READ|OP_WRITE */
    {
        fd_selector s = selector_new(8);
        int sp[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        set_nonblock(sp[0]);
        set_nonblock(sp[1]);

        uint8_t rbuf[64], wbuf[64];
        buffer rb, wb;
        buffer_init(&rb, sizeof(rbuf), rbuf);
        buffer_init(&wb, sizeof(wbuf), wbuf);
        buffer_write(&wb, 0xAB);   /* wb tiene algo para enviar -> OP_WRITE */

        int fd = sp[0];
        struct copy c;
        memset(&c, 0, sizeof(c));
        c.fd = &fd; c.rb = &rb; c.wb = &wb;
        c.duplex = OP_READ | OP_WRITE; c.other = NULL;
        c.key.s = s; c.key.fd = fd; c.key.data = NULL;

        selector_register(s, fd, &OBS_HANDLER, OP_NOOP, NULL);
        selector_status st = copy_compute_interests(&c);
        CHECK(st == SELECTOR_SUCCESS, "1: compute_interests devuelve SUCCESS");

        bool gr, gw;
        observe_interest(s, sp[1], &gr, &gw);
        CHECK(gr, "1: rb con espacio y duplex READ -> interesa OP_READ");
        CHECK(gw, "1: wb con datos y duplex WRITE -> interesa OP_WRITE");

        selector_unregister_fd(s, fd);
        close(sp[0]); close(sp[1]);
        selector_destroy(s);
    }

    /* --- 2: rb LLENO (backpressure) apaga OP_READ aunque duplex tenga READ --- */
    {
        fd_selector s = selector_new(8);
        int sp[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        set_nonblock(sp[0]);
        set_nonblock(sp[1]);

        uint8_t rbuf[4], wbuf[64];
        buffer rb, wb;
        buffer_init(&rb, sizeof(rbuf), rbuf);
        buffer_init(&wb, sizeof(wbuf), wbuf);
        /* llenar rb hasta el tope: buffer_can_write(rb) == false */
        size_t cap;
        uint8_t *p = buffer_write_ptr(&rb, &cap);
        memset(p, 0, cap);
        buffer_write_adv(&rb, (ssize_t) cap);
        CHECK(!buffer_can_write(&rb), "2: precondición rb lleno");

        int fd = sp[0];
        struct copy c;
        memset(&c, 0, sizeof(c));
        c.fd = &fd; c.rb = &rb; c.wb = &wb;
        c.duplex = OP_READ | OP_WRITE; c.other = NULL;
        c.key.s = s; c.key.fd = fd; c.key.data = NULL;

        selector_register(s, fd, &OBS_HANDLER, OP_NOOP, NULL);
        (void) copy_compute_interests(&c);

        bool gr, gw;
        observe_interest(s, sp[1], &gr, &gw);
        CHECK(!gr, "2: rb lleno -> NO interesa OP_READ (backpressure)");
        CHECK(!gw, "2: wb vacío -> NO interesa OP_WRITE");

        selector_unregister_fd(s, fd);
        close(sp[0]); close(sp[1]);
        selector_destroy(s);
    }

    /* --- 3: duplex sin OP_READ (medio cerrado en lectura) -> solo OP_WRITE --- */
    {
        fd_selector s = selector_new(8);
        int sp[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        set_nonblock(sp[0]);
        set_nonblock(sp[1]);

        uint8_t rbuf[64], wbuf[64];
        buffer rb, wb;
        buffer_init(&rb, sizeof(rbuf), rbuf);
        buffer_init(&wb, sizeof(wbuf), wbuf);
        buffer_write(&wb, 0x01);   /* hay para escribir */

        int fd = sp[0];
        struct copy c;
        memset(&c, 0, sizeof(c));
        c.fd = &fd; c.rb = &rb; c.wb = &wb;
        c.duplex = OP_WRITE;   /* OP_READ apagado */
        c.other = NULL;
        c.key.s = s; c.key.fd = fd; c.key.data = NULL;

        selector_register(s, fd, &OBS_HANDLER, OP_NOOP, NULL);
        (void) copy_compute_interests(&c);

        bool gr, gw;
        observe_interest(s, sp[1], &gr, &gw);
        CHECK(!gr, "3: duplex sin OP_READ -> NO interesa OP_READ");
        CHECK(gw, "3: duplex con OP_WRITE y wb con datos -> interesa OP_WRITE");

        selector_unregister_fd(s, fd);
        close(sp[0]); close(sp[1]);
        selector_destroy(s);
    }

    /* --- 4: nada para hacer (duplex WRITE pero wb vacío) -> OP_NOOP --- */
    {
        fd_selector s = selector_new(8);
        int sp[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        set_nonblock(sp[0]);
        set_nonblock(sp[1]);

        uint8_t rbuf[64], wbuf[64];
        buffer rb, wb;
        buffer_init(&rb, sizeof(rbuf), rbuf);
        buffer_init(&wb, sizeof(wbuf), wbuf);
        /* wb vacío -> nada para enviar; duplex sin READ -> nada para recibir */

        int fd = sp[0];
        struct copy c;
        memset(&c, 0, sizeof(c));
        c.fd = &fd; c.rb = &rb; c.wb = &wb;
        c.duplex = OP_WRITE; c.other = NULL;
        c.key.s = s; c.key.fd = fd; c.key.data = NULL;

        selector_register(s, fd, &OBS_HANDLER, OP_NOOP, NULL);
        (void) copy_compute_interests(&c);

        bool gr, gw;
        observe_interest(s, sp[1], &gr, &gw);
        CHECK(!gr && !gw, "4: nada para hacer -> OP_NOOP (ningún handler dispara)");

        selector_unregister_fd(s, fd);
        close(sp[0]); close(sp[1]);
        selector_destroy(s);
    }

    /* --- 5: fd inválido -> SELECTOR_IARGS, sin tocar el selector --- */
    {
        struct copy c;
        memset(&c, 0, sizeof(c));
        int bad = -1;
        c.fd = &bad;
        CHECK(copy_compute_interests(&c) == SELECTOR_IARGS,
              "5: fd == -1 -> SELECTOR_IARGS");
        CHECK(copy_compute_interests(NULL) == SELECTOR_IARGS,
              "5: copy NULL -> SELECTOR_IARGS");
    }

    /* ===================================================================
     * Grupo 2: copy_read / copy_write / half-close / -> DONE
     * Se arma un struct socks5 mínimo a mano (sin pool).
     * =================================================================== */

    /* --- 6: half-close: EOF en client_fd hace shutdown(SHUT_WR) sobre origin,
     *        el peer del origin observa EOF en recv(). --- */
    {
        fd_selector s = selector_new(16);

        int cli[2], ori[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, cli);
        socketpair(AF_UNIX, SOCK_STREAM, 0, ori);
        for (int i = 0; i < 2; i++) { set_nonblock(cli[i]); set_nonblock(ori[i]); }

        struct socks5 s5;
        uint8_t raw_a[IO_BUFFER_SIZE];
        uint8_t raw_b[IO_BUFFER_SIZE];
        memset(&s5, 0, sizeof(s5));
        s5.client_fd = cli[0];
        s5.origin_fd = ori[0];
        s5.raw_buff_a = raw_a;
        s5.raw_buff_b = raw_b;
        s5.raw_buff_size = IO_BUFFER_SIZE;
        buffer_init(&s5.read_buffer,  s5.raw_buff_size, s5.raw_buff_a);
        buffer_init(&s5.write_buffer, s5.raw_buff_size, s5.raw_buff_b);

        selector_register(s, cli[0], &OBS_HANDLER, OP_NOOP, &s5);
        selector_register(s, ori[0], &OBS_HANDLER, OP_NOOP, &s5);

        struct selector_key kinit = { .s = s, .fd = cli[0], .data = &s5 };
        copy_init(COPY, &kinit);

        /* el cliente cierra su lado de escritura -> recv() del proxy da 0 */
        shutdown(cli[1], SHUT_WR);

        struct selector_key kread = { .s = s, .fd = cli[0], .data = &s5 };
        unsigned next = copy_read(&kread);
        CHECK(next == COPY || next == DONE,
              "6: copy_read tras EOF de cliente no marca ERROR");

        /* el shutdown(SHUT_WR) sobre origin_fd debe propagar EOF al peer */
        char tmp[8];
        ssize_t r = recv(ori[1], tmp, sizeof(tmp), 0);
        CHECK(r == 0, "6: half-close propaga EOF al peer del origin (recv == 0)");

        selector_unregister_fd(s, cli[0]);
        selector_unregister_fd(s, ori[0]);
        close(cli[0]); close(cli[1]); close(ori[0]); close(ori[1]);
        selector_destroy(s);
    }

    /* --- 7: copy_next_state -> DONE cuando ambos sentidos cerraron en lectura
     *        y no quedan bytes pendientes en ningún buffer. --- */
    {
        fd_selector s = selector_new(16);

        int cli[2], ori[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, cli);
        socketpair(AF_UNIX, SOCK_STREAM, 0, ori);
        for (int i = 0; i < 2; i++) { set_nonblock(cli[i]); set_nonblock(ori[i]); }

        struct socks5 s5;
        uint8_t raw_a[IO_BUFFER_SIZE];
        uint8_t raw_b[IO_BUFFER_SIZE];
        memset(&s5, 0, sizeof(s5));
        s5.client_fd = cli[0];
        s5.origin_fd = ori[0];
        s5.raw_buff_a = raw_a;
        s5.raw_buff_b = raw_b;
        s5.raw_buff_size = IO_BUFFER_SIZE;
        buffer_init(&s5.read_buffer,  s5.raw_buff_size, s5.raw_buff_a);
        buffer_init(&s5.write_buffer, s5.raw_buff_size, s5.raw_buff_b);

        selector_register(s, cli[0], &OBS_HANDLER, OP_NOOP, &s5);
        selector_register(s, ori[0], &OBS_HANDLER, OP_NOOP, &s5);

        struct selector_key kinit = { .s = s, .fd = cli[0], .data = &s5 };
        copy_init(COPY, &kinit);

        /* ambos extremos cierran su escritura -> ambos lados ven EOF */
        shutdown(cli[1], SHUT_WR);
        shutdown(ori[1], SHUT_WR);

        struct selector_key kc = { .s = s, .fd = cli[0], .data = &s5 };
        struct selector_key ko = { .s = s, .fd = ori[0], .data = &s5 };
        (void) copy_read(&kc);
        unsigned last = copy_read(&ko);
        CHECK(last == DONE,
              "7: ambos sentidos cerrados y buffers vacíos -> copy_next_state == DONE");

        selector_unregister_fd(s, cli[0]);
        selector_unregister_fd(s, ori[0]);
        close(cli[0]); close(cli[1]); close(ori[0]); close(ori[1]);
        selector_destroy(s);
    }

    /* --- 8: transferencia real client->origin: copy_read del cliente carga el
     *        buffer y copy_write del origin lo drena hacia su peer. --- */
    {
        fd_selector s = selector_new(16);

        int cli[2], ori[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, cli);
        socketpair(AF_UNIX, SOCK_STREAM, 0, ori);
        for (int i = 0; i < 2; i++) { set_nonblock(cli[i]); set_nonblock(ori[i]); }

        struct socks5 s5;
        uint8_t raw_a[IO_BUFFER_SIZE];
        uint8_t raw_b[IO_BUFFER_SIZE];
        memset(&s5, 0, sizeof(s5));
        s5.client_fd = cli[0];
        s5.origin_fd = ori[0];
        s5.raw_buff_a = raw_a;
        s5.raw_buff_b = raw_b;
        s5.raw_buff_size = IO_BUFFER_SIZE;
        buffer_init(&s5.read_buffer,  s5.raw_buff_size, s5.raw_buff_a);
        buffer_init(&s5.write_buffer, s5.raw_buff_size, s5.raw_buff_b);

        selector_register(s, cli[0], &OBS_HANDLER, OP_NOOP, &s5);
        selector_register(s, ori[0], &OBS_HANDLER, OP_NOOP, &s5);

        struct selector_key kinit = { .s = s, .fd = cli[0], .data = &s5 };
        copy_init(COPY, &kinit);

        const char *payload = "hola-relay";
        metrics_init();
        (void) write(cli[1], payload, strlen(payload));

        struct selector_key kc = { .s = s, .fd = cli[0], .data = &s5 };
        unsigned r1 = copy_read(&kc);   /* carga read_buffer (rb del cliente) */
        CHECK(r1 == COPY, "8: copy_read del cliente sigue en COPY");
        CHECK(metrics_get()->bytes_transferred == strlen(payload),
              "8: copy_read suma bytes reales a métricas");

        struct selector_key ko = { .s = s, .fd = ori[0], .data = &s5 };
        unsigned r2 = copy_write(&ko);  /* drena hacia ori[0] -> peer ori[1] */
        CHECK(r2 == COPY, "8: copy_write del origin sigue en COPY");

        char got[64];
        ssize_t n = recv(ori[1], got, sizeof(got), 0);
        CHECK(n == (ssize_t) strlen(payload) &&
              memcmp(got, payload, strlen(payload)) == 0,
              "8: el payload del cliente llega íntegro al peer del origin");

        selector_unregister_fd(s, cli[0]);
        selector_unregister_fd(s, ori[0]);
        close(cli[0]); close(cli[1]); close(ori[0]); close(ori[1]);
        selector_destroy(s);
    }

    selector_close();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
