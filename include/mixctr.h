#ifndef MIXCTR_H
#define MIXCTR_H

#include "types.h"

#include <stdlib.h>

// A function that implements MixCTR on a series of 48-B blocks.
// Here `size` must be a multiple of `SIZE_MACRO` (48).
typedef int (*mixctrpass_impl_t)(byte *in, byte *out, size_t size);

// Accepted AES implementations for MixCTR.
typedef enum {
        MIXCTR_WOLFSSL,
        MIXCTR_OPENSSL,
        MIXCTR_AESNI,
        MIXCTR_OPENSSL_SHA3_256,
        MIXCTR_OPENSSL_BLAKE2S_256,
        MIXCTR_OPENSSL_SHA3_512,
        MIXCTR_OPENSSL_BLAKE2B_512,
        MIXCTR_OPENSSL_SHAKE128_1536,
        MIXCTR_OPENSSL_SHAKE256_1536,
        MIXCTR_WOLFCRYPT_SHA3_256,
        MIXCTR_WOLFCRYPT_BLAKE2S_256,
        MIXCTR_WOLFCRYPT_SHA3_512,
        MIXCTR_WOLFCRYPT_BLAKE2B_512,
        MIXCTR_WOLFCRYPT_SHAKE128_1536,
        MIXCTR_WOLFCRYPT_SHAKE256_1536,
} mixctr_t;

// Obtains the corresponding MixCTR function given a certain AES implmmentation.
mixctrpass_impl_t get_mixctr_impl(mixctr_t name);

#endif
