#ifndef UTILS_H
#define UTILS_H

#include <math.h> // For logarithm

#include "config.h"
#include "types.h"

#ifdef NO_MEASURE
#define MEASURE(F) 0
#else
#include <time.h>
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

#define CEILDIV(a, b) ((__typeof__(a))ceil((double)(a) / (b)))

byte *checked_malloc(size_t size);

// Does `dst = a ^ b` but on memory areas. Size is specified in bytes.
void memxor(void *dst, void *a, void *b, size_t bytes);

// Swaps two memory areas.
void memswap(byte *a, byte *b, size_t bytes);

// Applies `explicit_bzero` to `ptr` if it is not `NULL`.
void safe_explicit_bzero(void *ptr, size_t size);

// Power over 64-bit integers.
uint64_t intpow(uint64_t base, uint64_t exp);

#endif
