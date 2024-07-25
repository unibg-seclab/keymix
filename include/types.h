#ifndef TYPES_H_
#define TYPES_H_

#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

// Custom common types
typedef unsigned char byte;

typedef __uint128_t uint128_t;

#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)
#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef struct {
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
        uint8_t diff_factor; // diffusion factor (swap function): 3 (128 bits), 4
                             // (96 bits), 6 (64 bits), 12 (32 bits)
} mixing_config;

typedef struct {
        uint8_t thread_id;
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
        uint8_t thread_levels;
        uint8_t total_levels;
        mixing_config *mixconfig;
} thread_data;

typedef struct {
        byte *out;
        byte *secret;
        size_t seed_size;
        mixing_config *mixconfig;
} inter_keymix_data;

typedef struct {
        byte *out;
        byte *secret;
        size_t seed_size;
        mixing_config *mixconfig;
        unsigned int nof_threads;
} inter_intra_keymix_data;

struct arguments {
        char *resource_path;
        char *output_path;
        char *secret_path;
        byte *iv;
        unsigned int diffusion;
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
        unsigned int threads;
        unsigned short verbose;
        // other
        char *mixfunc_descr;
};

typedef union {
        long value;
        char array[8];
} counter;

#endif // TYPES_H_
