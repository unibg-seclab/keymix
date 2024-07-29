#ifndef UTILS_H
#define UTILS_H

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

byte *checked_malloc(size_t size);
void memxor(void *dst, void *src, size_t size);
void memswap(byte *a, byte *b, size_t bytes);
void memxor_ex(void *dst, void *a, void *b, size_t size);
void safe_explicit_bzero(void *ptr, size_t size);

uint64_t intpow(uint64_t base, uint64_t exp);

#endif
