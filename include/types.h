#ifndef TYPES_H
#define TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"

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

#endif
