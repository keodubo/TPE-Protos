#include "dbg.h"
#include <stdlib.h>   // getenv

bool
dbg_parse(const char *env) {
    if (env == NULL || env[0] == '\0') {
        return false;
    }
    if (env[0] == '0' && env[1] == '\0') {   // exactamente "0"
        return false;
    }
    return true;
}

bool
dbg_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        cached = dbg_parse(getenv("SOCKS5_DEBUG")) ? 1 : 0;
    }
    return cached == 1;
}
