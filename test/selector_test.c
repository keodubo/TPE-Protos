#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <check.h>

#define INITIAL_SIZE ((size_t) 1024)

// para poder testear las funciones estaticas
#include "selector.c"

START_TEST (test_selector_error) {
    const selector_status data[] = {
        SELECTOR_SUCCESS,
        SELECTOR_ENOMEM,
        SELECTOR_MAXFD,
        SELECTOR_IARGS,
        SELECTOR_IO,
    };
    // verifica que `selector_error' tiene mensajes especificos
    for(unsigned i = 0 ; i < N(data); i++) {
        ck_assert_str_ne(ERROR_DEFAULT_MSG, selector_error(data[i]));
    }
}
END_TEST

START_TEST (test_next_capacity) {
    const size_t data[] = {
         0,  1,
         1,  2,
         2,  4,
         3,  4,
         4,  8,
         7,  8,
         8, 16,
        15, 16,
        31, 32,
        16, 32,
        ITEMS_MAX_SIZE, ITEMS_MAX_SIZE,
        ITEMS_MAX_SIZE + 1, ITEMS_MAX_SIZE,
    };
    for(unsigned i = 0; i < N(data) / 2; i++ ) {
        ck_assert_uint_eq(data[i * 2 + 1] + 1, next_capacity(data[i*2]));
    }
}
END_TEST

START_TEST (test_ensure_capacity) {
    fd_selector s = selector_new(0);
    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    size_t n = 1;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    n = 10;
    ck_assert_int_eq(SELECTOR_SUCCESS, ensure_capacity(s, n));
    ck_assert_uint_ge(s->fd_size, n);

    const size_t last_size = s->fd_size;
    n = ITEMS_MAX_SIZE + 1;
    ck_assert_int_eq(SELECTOR_MAXFD, ensure_capacity(s, n));
    ck_assert_uint_eq(last_size, s->fd_size);

    for(size_t i = 0; i < s->fd_size; i++) {
        ck_assert_int_eq(FD_UNUSED, s->fds[i].fd);
    }

    selector_destroy(s);

    ck_assert_ptr_null(selector_new(ITEMS_MAX_SIZE + 1));
}
END_TEST

// callbacks de prueba
static void *data_mark = (void *)0x0FF1CE;
static unsigned destroy_count = 0;
static void
destroy_callback(struct selector_key *key) {
    ck_assert_ptr_nonnull(key->s);
    ck_assert_int_ge(key->fd, 0);
    ck_assert_int_lt(key->fd, ITEMS_MAX_SIZE);

    ck_assert_ptr_eq(data_mark, key->data);
    destroy_count++;
}

START_TEST (test_selector_register_fd) {
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    ck_assert_uint_eq(SELECTOR_IARGS,   selector_register(0, -1, 0, 0, data_mark));

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    const struct item *item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    // destroy desregistró?
    ck_assert_uint_eq(1,          destroy_count);

}
END_TEST

START_TEST (test_selector_register_unregister_register) {
    destroy_count = 0;
    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);

    const struct fd_handler h = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_close  = destroy_callback,
    };
    int fd = ITEMS_MAX_SIZE - 1;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_unregister_fd(s, fd));

    const struct item *item = s->fds + fd;
    ck_assert_int_eq (0,          s->max_fd);
    ck_assert_int_eq (FD_UNUSED,  item->fd);
    ck_assert_ptr_eq (0x00,       item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (0x00,       item->data);

    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h, 0, data_mark));
    item = s->fds + fd;
    ck_assert_int_eq (fd,         s->max_fd);
    ck_assert_int_eq (fd,         item->fd);
    ck_assert_ptr_eq (&h,         item->handler);
    ck_assert_uint_eq(0,          item->interest);
    ck_assert_ptr_eq (data_mark,  item->data);

    selector_destroy(s);
    ck_assert_uint_eq(2,          destroy_count);

}
END_TEST

// ---------------------------------------------------------------------------
// f12: handle_block_notifications debe tolerar un handler con handle_block=NULL
// (p.ej. el handler de origin_fd) sin crashear, y debe invocar el callback
// cuando handle_block != NULL. Se ejercita el path estatico directamente
// (selector.c esta #incluido), encolando un job con selector_notify_block.
// ---------------------------------------------------------------------------
static unsigned block_count = 0;
static void
block_callback(struct selector_key *key) {
    ck_assert_ptr_nonnull(key->s);
    ck_assert_int_ge(key->fd, 0);
    ck_assert_ptr_eq(data_mark, key->data);
    block_count++;
}

START_TEST (test_handle_block_null_handler_no_crash) {
    // selector_notify_block hace pthread_kill(selector_thread, conf.signal);
    // inicializamos un signal real y apuntamos el "selector_thread" a este hilo
    // para que la notificacion sea inocua en el contexto del test.
    const struct selector_init c = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 0 },
    };
    ck_assert_int_eq(0, selector_init(&c));

    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);
    s->selector_thread = pthread_self();

    // handler SIN handle_block (como socks5_origin_handler).
    const struct fd_handler h_null = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_block  = NULL,
        .handle_close  = NULL,
    };
    const int fd = 7;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h_null, OP_NOOP, data_mark));

    // encolar el block y procesarlo: NO debe desreferenciar el NULL.
    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block(s, fd));
    handle_block_notifications(s);   // si no hay guarda de NULL, segfault aqui

    selector_destroy(s);
    selector_close();
}
END_TEST

START_TEST (test_handle_block_invokes_callback) {
    const struct selector_init c = {
        .signal = SIGUSR1,
        .select_timeout = { .tv_sec = 0, .tv_nsec = 0 },
    };
    ck_assert_int_eq(0, selector_init(&c));

    fd_selector s = selector_new(INITIAL_SIZE);
    ck_assert_ptr_nonnull(s);
    s->selector_thread = pthread_self();

    block_count = 0;
    const struct fd_handler h_block = {
        .handle_read   = NULL,
        .handle_write  = NULL,
        .handle_block  = block_callback,
        .handle_close  = NULL,
    };
    const int fd = 9;
    ck_assert_uint_eq(SELECTOR_SUCCESS,
                      selector_register(s, fd, &h_block, OP_NOOP, data_mark));

    ck_assert_uint_eq(SELECTOR_SUCCESS, selector_notify_block(s, fd));
    handle_block_notifications(s);
    ck_assert_uint_eq(1, block_count);   // el callback se invoco exactamente 1 vez

    selector_destroy(s);
    selector_close();
}
END_TEST

Suite *
suite(void) {
    Suite *s  = suite_create("nio");
    TCase *tc = tcase_create("nio");

    tcase_add_test(tc, test_next_capacity);
    tcase_add_test(tc, test_selector_error);
    tcase_add_test(tc, test_ensure_capacity);
    tcase_add_test(tc, test_selector_register_fd);
    tcase_add_test(tc, test_selector_register_unregister_register);
    tcase_add_test(tc, test_handle_block_null_handler_no_crash);
    tcase_add_test(tc, test_handle_block_invokes_callback);
    suite_add_tcase(s, tc);

    return s;
}

int 
main(void) {
    int number_failed;
    SRunner *sr = srunner_create(suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

