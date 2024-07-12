#ifndef UTILS_H
#define UTILS_H

#include "config.h"
#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

byte *checked_malloc(size_t size);
void print_buffer_hex(byte *buf, size_t size, char *descr);

void shuffle(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout);
void shuffle_opt(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout);
void shuffle_opt2(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout);

void swap(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int diff_factor);
void swap_chunks(thread_data *args, int level);

#define D if (DEBUG)
#define LOG(...) fprintf(stderr, __VA_ARGS__)

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

#define MAX(a, b)                                                                                  \
        ({                                                                                         \
                __typeof__(a) _a = (a);                                                            \
                __typeof__(b) _b = (b);                                                            \
                _a > _b ? _a : _b;                                                                 \
        })

#endif
