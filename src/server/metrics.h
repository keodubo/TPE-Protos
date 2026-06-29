#ifndef METRICS_H_TPE_SOCKS5
#define METRICS_H_TPE_SOCKS5

#include <stddef.h>

struct socks_metrics {
    unsigned long      historic_connections;
    unsigned long      current_connections;
    unsigned long      failed_connections;
    unsigned long      current_users;
    unsigned long long bytes_transferred;
};

void metrics_init(void);
void metrics_connection_opened(void);
void metrics_connection_closed(void);
void metrics_connection_failed(void);
void metrics_add_bytes(size_t n);
const struct socks_metrics *metrics_get(void);

#endif
