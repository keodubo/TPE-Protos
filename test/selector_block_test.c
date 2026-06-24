/*
 * selector_block_test.c - tests blackbox del handoff de jobs bloqueantes.
 * Harness plano en C (sin libcheck). Correr con: make test
 */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#include "selector.h"

static int checks = 0, failures = 0;

#define CHECK(cond, msg) do {                                  \
    checks++;                                                  \
    if (cond) { printf("  ok  - %s\n", msg); }                 \
    else      { printf("  FAIL- %s\n", msg); failures++; }     \
} while (0)

static unsigned block_count;
static unsigned cleanup_count;
static void *block_data;
static void *cleanup_data;

static void
block_callback(struct selector_key *key) {
    block_count++;
    block_data = key->data;
}

static void
cleanup_callback(struct selector_key *key) {
    cleanup_count++;
    cleanup_data = key->data;
}

static fd_selector
new_test_selector(void) {
    const struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 0 },
    };
    if (selector_init(&conf) != SELECTOR_SUCCESS) {
        return NULL;
    }

    fd_selector s = selector_new(16);
    if (s != NULL) {
        /* Inicializa selector_thread para que notify pueda señalizar a este hilo. */
        (void) selector_select(s);
    }
    return s;
}

static void
reset_counters(void) {
    block_count = 0;
    cleanup_count = 0;
    block_data = NULL;
    cleanup_data = NULL;
}

static void
test_block_job_with_matching_data_dispatches_and_cleans_up(void) {
    reset_counters();
    fd_selector s = new_test_selector();
    CHECK(s != NULL, "1: selector creado");

    int sp[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "1: socketpair creado");

    char attachment = 'A';
    const struct fd_handler h = {
        .handle_block = block_callback,
    };
    CHECK(selector_register(s, sp[0], &h, OP_NOOP, &attachment) == SELECTOR_SUCCESS,
          "1: fd registrado");

    CHECK(selector_notify_block_with_data(s, sp[0], &attachment, cleanup_callback)
              == SELECTOR_SUCCESS,
          "1: notify con identidad devuelve SUCCESS");
    CHECK(selector_select(s) == SELECTOR_SUCCESS, "1: selector procesa el job");

    CHECK(block_count == 1, "1: identidad coincide -> dispatch al callback");
    CHECK(block_data == &attachment, "1: callback recibe el attachment vivo");
    CHECK(cleanup_count == 1, "1: cleanup corre después del job");
    CHECK(cleanup_data == &attachment, "1: cleanup recibe el attachment esperado");

    selector_unregister_fd(s, sp[0]);
    close(sp[0]);
    close(sp[1]);
    selector_destroy(s);
    selector_close();
}

static void
test_block_job_with_stale_data_only_cleans_up(void) {
    reset_counters();
    fd_selector s = new_test_selector();
    CHECK(s != NULL, "2: selector creado");

    int sp[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "2: socketpair creado");

    char old_attachment = 'O';
    char new_attachment = 'N';
    const struct fd_handler h = {
        .handle_block = block_callback,
    };
    CHECK(selector_register(s, sp[0], &h, OP_NOOP, &new_attachment)
              == SELECTOR_SUCCESS,
          "2: fd reutilizado registrado con otro attachment");

    CHECK(selector_notify_block_with_data(s, sp[0], &old_attachment, cleanup_callback)
              == SELECTOR_SUCCESS,
          "2: notify viejo encolado para mismo fd");
    CHECK(selector_select(s) == SELECTOR_SUCCESS, "2: selector procesa el job");

    CHECK(block_count == 0, "2: identidad stale -> NO dispara sobre conexión nueva");
    CHECK(cleanup_count == 1, "2: identidad stale -> cleanup igual corre");
    CHECK(cleanup_data == &old_attachment, "2: cleanup recibe el attachment viejo");

    selector_unregister_fd(s, sp[0]);
    close(sp[0]);
    close(sp[1]);
    selector_destroy(s);
    selector_close();
}

int
main(void) {
    test_block_job_with_matching_data_dispatches_and_cleans_up();
    test_block_job_with_stale_data_only_cleans_up();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
