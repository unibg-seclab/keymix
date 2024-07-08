#ifndef TYPES_H
#define TYPES_H

#include <semaphore.h>
#include <stdlib.h>

#define SIZE_MACRO 48
#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)
#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef unsigned char byte;

typedef struct {
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
        char *descr;
        unsigned int diff_factor;
} mixing_config;

typedef struct {
        unsigned int thread_id;
        sem_t *thread_sem;
        sem_t *coord_sem;
        byte *in;
        byte *out;
        byte *swp;
        byte *abs_out;
        byte *abs_swp;
        size_t seed_size;
        size_t thread_chunk_size;
        unsigned int diff_factor;
        unsigned int thread_levels;
        unsigned int total_levels;
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
} thread_data;

#endif
