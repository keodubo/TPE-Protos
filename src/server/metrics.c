#include "metrics.h"

static struct socks_metrics metrics;

void
metrics_init(void) {
    metrics = (struct socks_metrics) {0};
}

void
metrics_connection_opened(void) {
    metrics.historic_connections++;
    metrics.current_connections++;
}

void
metrics_connection_closed(void) {
    if (metrics.current_connections > 0) {
        metrics.current_connections--;
    }
}

void
metrics_connection_failed(void) {
    metrics.failed_connections++;
}

void
metrics_add_bytes(const size_t n) {
    /*
     * M6 define contadores volatiles desde el arranque; no hacemos defensa de
     * overflow porque unsigned long long alcanza de sobra para el alcance del TP.
     */
    metrics.bytes_transferred += (unsigned long long) n;
}

const struct socks_metrics *
metrics_get(void) {
    return &metrics;
}
