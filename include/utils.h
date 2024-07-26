#ifndef UTILS_H_
#define UTILS_H_

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h"
#include "types.h"

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

#define LOGBASE(x, base) (round(log(x) / log(base)))
#define ISPOWEROF(x, base) (x == pow(base, (int)LOGBASE(x, base)))

mixctrpass_impl_t get_mixctr_impl(mixctrpass_t name);
byte *checked_malloc(size_t size);
void increment_counter(byte *macro, unsigned long step);
void memxor(void *dst, void *src, size_t size);
void memxor_ex(void *dst, void *a, void *b, size_t size);
void safe_explicit_bzero(void *ptr, size_t size);
uint8_t total_levels(size_t seed_size, uint8_t fanout);

typedef struct {
        uint8_t thread_id;

        byte *buffer;
        size_t buffer_size;

        byte *buffer_abs;
        size_t buffer_abs_size;

        uint8_t thread_levels;
        uint8_t total_levels;
        uint8_t fanout;
} spread_inplace_chunks_t;

void spread_inplace(byte *buffer, size_t size, uint8_t level, uint8_t fanout);
void spread_chunks_inplace(spread_inplace_chunks_t *args, uint8_t level);

#endif // UTILS_H_
