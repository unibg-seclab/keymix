#ifndef TYPES_H
#define TYPES_H

#include <stdlib.h>

// Custom common types
typedef unsigned char byte;

// sizes
#define SIZE_MACRO 48
#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)

// current limit
#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef struct {
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro);
        char *descr;
        unsigned int blocks_per_macro; // number of 128-bit blocks in each macro
        unsigned int diff_factor;      // diffusion factor (swap functio): 3 (128 bits), 4
                                       // (96 bits), 6 (64 bits), 12 (32 bits)
} mixing_config;

#endif
