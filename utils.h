#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <time.h>

#include "config.h"
#include "types.h"

void memxor(byte *dst, byte *src, size_t n);

byte *checked_malloc(size_t size);

void print_buffer_hex(byte *buf, size_t size, char *descr);

unsigned long get_current_time_millis();

#define D if (DEBUG)
#define LOG(...) D printf(__VA_ARGS__)

#ifdef NO_MEASURE
#define MEASURE(F) 0
#define PRINT_TIME_DELTA(DESC, MS)
#else
#define PRINT_TIME_DELTA(DESC, MS) LOG("%s: %.2f", (DESC), (MS));
#define MEASURE(F)                                                                                 \
        ({                                                                                         \
                double t;                                                                          \
                struct timespec start, end;                                                        \
                clock_gettime(CLOCK_MONOTONIC, &start);                                            \
                do {                                                                               \
                        F;                                                                         \
                } while (0);                                                                       \
                clock_gettime(CLOCK_MONOTONIC, &end);                                              \
                t = (end.tv_sec - start.tv_sec);                                                   \
                t += (end.tv_nsec - start.tv_nsec) / 1000000000.0;                                 \
                t *= 1000;                                                                         \
                t;                                                                                 \
        })
#endif

#endif
