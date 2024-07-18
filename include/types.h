#ifndef TYPES_H
#define TYPES_H

#include "config.h"
#include <semaphore.h>

// Custom common types
typedef unsigned char byte;

#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)

#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef struct {
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
        unsigned int diff_factor; // diffusion factor (swap functio): 3 (128 bits), 4
                                  // (96 bits), 6 (64 bits), 12 (32 bits)
} mixing_config;

typedef struct {
        unsigned int thread_id;
        sem_t *thread_sem;
        sem_t *coord_sem;
        byte *in;
        byte *out;
        byte *buf;
        byte *abs_in;
        byte *abs_out;
        byte *abs_buf;
        size_t seed_size;
        size_t thread_chunk_size;
        unsigned int thread_levels;
        unsigned int total_levels;
        mixing_config *mixconfig;
} thread_data;

#endif
