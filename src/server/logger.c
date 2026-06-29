#include "logger.h"

#include <time.h>

#include "netutils.h"

static FILE *log_out;

void
logger_init(FILE *out) {
    log_out = out == NULL ? stdout : out;
}

void
logger_log_access(const char *username,
                  const struct sockaddr *client,
                  const char *dest_host,
                  const unsigned dest_port,
                  const enum access_result result) {
    if (log_out == NULL) {
        logger_init(NULL);
    }

    time_t now = time(NULL);
    struct tm utc;
    char timestamp[sizeof("1970-01-01T00:00:00Z")];
    if (gmtime_r(&now, &utc) == NULL
            || strftime(timestamp, sizeof(timestamp),
                        "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        timestamp[0] = '\0';
    }

    char client_human[SOCKADDR_TO_HUMAN_MIN];
    sockaddr_to_human(client_human, sizeof(client_human), client);

    const char *user = username == NULL || username[0] == '\0' ? "-" : username;
    const char *host = dest_host == NULL || dest_host[0] == '\0' ? "-" : dest_host;
    const char *status = result == ACCESS_OK ? "OK" : "FAIL";

    fprintf(log_out, "%s\t%s\t%s\t%s:%u\t%s\n",
            timestamp, user, client_human, host, dest_port, status);
    fflush(log_out);
}
