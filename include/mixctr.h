#ifndef MIXCTR_H
#define MIXCTR_H

#include "types.h"

#include <stdlib.h>

// A function that implements MixCTR on a 48-B block.
typedef int (*mixctr_impl_t)(byte *key, uint128_t *data, size_t blocks_per_macro, byte *out);

// Accepted AES implementations for MixCTR.
typedef enum {
        MIXCTR_WOLFSSL,
        MIXCTR_OPENSSL,
        MIXCTR_AESNI,
} mixctr_t;

// Obtains the corresponding MixCTR function given a certain AES implmmentation.
// Also gets the correct macro size (for now, always 48 B).
// Returns 0 on success, 1 if the given implementation does not exists.
int get_mixctr_impl(mixctr_t name, mixctr_impl_t *impl, size_t *size_macro);

#endif
