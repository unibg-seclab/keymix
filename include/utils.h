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

double MiB(size_t size);

byte *checked_malloc(size_t size);
size_t get_file_size(FILE *fstr);
void increment_counter(byte *macro, unsigned long step);
void memxor(void *dst, void *src, size_t size);
void print_buffer_hex(byte *buf, size_t size, char *descr);
void safe_explicit_bzero(void *ptr, size_t size);
uint8_t total_levels(size_t seed_size, uint8_t fanout);

void shuffle(byte *out, byte *in, size_t in_size, uint8_t level, uint8_t fanout);
void shuffle_opt(byte *out, byte *in, size_t in_size, uint8_t level, uint8_t fanout);
void shuffle_chunks(thread_data *args, uint8_t level);
void shuffle_chunks_opt(thread_data *args, uint8_t level);

void spread(byte *out, byte *in, size_t size, uint8_t level, uint8_t fanout);
void spread_inplace(byte *buffer, size_t size, uint8_t level, uint8_t fanout);
void spread_chunks(thread_data *args, uint8_t level);
void spread_chunks_inplace(thread_data *args, uint8_t level);

#endif // UTILS_H_
