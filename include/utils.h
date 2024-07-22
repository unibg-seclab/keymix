#ifndef UTILS_H
#define UTILS_H

#include "config.h"
#include "types.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void _log(log_level_t log_level, const char *fmt, ...);

void shuffle(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout);
void shuffle_opt(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout);

void swap(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int diff_factor);
void swap_chunks(thread_data *args, int level);

void spread(byte *out, byte *in, size_t size, unsigned int level, unsigned int fanout);
void spread_inplace(byte *buffer, size_t size, unsigned int level, unsigned int fanout);
void spread_chunks(thread_data *args, int level);

void shuffle_chunks(thread_data *args, int level);
void shuffle_chunks_opt(thread_data *args, int level);

double MiB(double size);

#ifdef NO_MEASURE
#define MEASURE(F) 0
#else
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

#define MIN(a, b)                                                                                  \
        ({                                                                                         \
                __typeof__(a) _a = (a);                                                            \
                __typeof__(b) _b = (b);                                                            \
                _a < _b ? _a : _b;                                                                 \
        })

#define LOGBASE(x, base) (log(x) / log(base))
#define ISPOWEROF(x, base) (x == pow(base, (int)LOGBASE(x, base)))

#endif
