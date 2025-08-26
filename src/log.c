#include "log.h"

#include <stdarg.h>
#include <stdio.h>

#include "config.h"

void _logf(log_level_t level, const char *fmt, ...) {
        if (level >= LOG_LEVEL) {
                va_list args;
                va_start(args, fmt);
                vfprintf(stderr, fmt, args);
                va_end(args);
        }
}
