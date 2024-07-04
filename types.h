#ifndef TYPES_H
#define TYPES_H

#include <stdlib.h>

// Custom common types
typedef unsigned char byte;

// sizes
#define SIZE_BLOCK 16
#define BLOCKS_PER_MACRO 3
#define SIZE_MACRO (BLOCKS_PER_MACRO * SIZE_BLOCK)

#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)

// current limit
#define SIZE_1GiB (1024 * SIZE_1MiB)

typedef struct {
        int (*mixfunc)(byte *seed, byte *out, size_t seed_size);
        char *descr;
        unsigned int diff_factor; // diffusion factor (swap functio): 3 (128 bits), 4
                                  // (96 bits), 6 (64 bits), 12 (32 bits)
} mixing_config;

#endif
