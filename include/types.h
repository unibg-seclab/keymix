#ifndef TYPES_H
#define TYPES_H

// Common header libraries
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef unsigned char byte;

typedef __uint128_t uint128_t;

#define SIZE_1KiB 1024
#define SIZE_1MiB (1024 * SIZE_1KiB)
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

#endif
