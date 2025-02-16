#ifndef LOG_H
#define LOG_H

#if DISABLE_LOG
#define _log(...)
#else
#define _log(...) _logf(__VA_ARGS__)
#endif

typedef enum {
        LOG_DEBUG,
        LOG_INFO,
        LOG_ERROR,
} log_level_t;

void _logf(log_level_t log_level, const char *fmt, ...);

#endif
