#ifndef TYPES_H
#define TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"

// Custom common types
typedef unsigned char byte;

typedef __uint128_t uint128_t;

#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)
#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef int (*mixctrpass_impl_t)(byte *in, byte *out, size_t size);

typedef enum {
        FANOUT2 = 2,
        FANOUT3 = 3,
        FANOUT4 = 4,
} fanout_t;

typedef enum {
        MIXCTR_WOLFSSL,
        MIXCTR_OPENSSL,
        MIXCTR_AESNI,
} mixctr_t;

typedef struct {
        mixctrpass_impl_t mixfunc;
        uint8_t diff_factor; // diffusion factor (swap function): 3 (128 bits), 4
                             // (96 bits), 6 (64 bits), 12 (32 bits)
} mixing_config;

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

typedef struct {
        char *input;
        char *output;
        char *secret_path;
        byte *iv;
        unsigned int fanout;
        mixctr_t mixfunc;
        unsigned int threads;
        unsigned short verbose;
} cli_args_t;

#endif
