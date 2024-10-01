#ifndef MIXCTR_H
#define MIXCTR_H

#include "types.h"

#include <stdlib.h>

// A function that implements MixCTR on a series of 48-B blocks.
// Here `size` must be a multiple of `SIZE_MACRO` (48).
typedef int (*mixctrpass_impl_t)(byte *in, byte *out, size_t size);

// Accepted AES implementations for MixCTR.
typedef enum {
        // Fixed-output functions
#if SIZE_MACRO == 16
        MIXCTR_OPENSSL_AES_128,
        MIXCTR_OPENSSL_DAVIES_MEYER_128,
        MIXCTR_OPENSSL_MATYAS_MEYER_OSEAS_128,
        MIXCTR_WOLFCRYPT_AES_128,
        MIXCTR_WOLFCRYPT_DAVIES_MEYER_128,
        MIXCTR_WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
#elif SIZE_MACRO == 32
        // 256-bit block size
        MIXCTR_OPENSSL_SHA3_256,
        MIXCTR_OPENSSL_BLAKE2S,
        MIXCTR_WOLFCRYPT_SHA3_256,
        MIXCTR_WOLFCRYPT_BLAKE2S,
        MIXCTR_BLAKE3_BLAKE3,
#elif SIZE_MACRO == 48
        // 384-bit block size
        MIXCTR_WOLFSSL,
        MIXCTR_OPENSSL,
        MIXCTR_AESNI,
#elif SIZE_MACRO == 64
        // 512-bit block size
        MIXCTR_OPENSSL_SHA3_512,
        MIXCTR_OPENSSL_BLAKE2B,
        MIXCTR_WOLFCRYPT_SHA3_512,
        MIXCTR_WOLFCRYPT_BLAKE2B,
#endif
        // Extendable-output functions (XOFs)
#if SIZE_MACRO <= 48
        // 384-bit internal state
        MIXCTR_XKCP_XOODYAK,
#endif
#if SIZE_MACRO <= 128
        // 1600-bit internal state: r=1088, c=512
        // NOTE: To ensure the maximum security strength of 256 bits, the block
        // size should be at least of 64 bytes.
        MIXCTR_OPENSSL_SHAKE256,
        MIXCTR_WOLFCRYPT_SHAKE256,
        MIXCTR_XKCP_TURBOSHAKE_256,
#endif
#if SIZE_MACRO <= 160
        // 1600-bit internal state: r=1344, c=256
        // NOTE: To ensure the maximum security strength of 128 bits, the block
        // size should be at least of 32 bytes.
        MIXCTR_OPENSSL_SHAKE128,
        MIXCTR_WOLFCRYPT_SHAKE128,
        MIXCTR_XKCP_TURBOSHAKE_128,
        MIXCTR_XKCP_KANGAROOTWELVE,
#endif
} mixctr_t;

const static mixctr_t MIX_TYPES[] = {
#if SIZE_MACRO == 16
        // 128-bit block size
        MIXCTR_OPENSSL_DAVIES_MEYER_128,
        MIXCTR_WOLFCRYPT_DAVIES_MEYER_128,
        MIXCTR_OPENSSL_MATYAS_MEYER_OSEAS_128,
        MIXCTR_WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
#elif SIZE_MACRO == 32
        // 256-bit block size
        MIXCTR_OPENSSL_SHA3_256,
        MIXCTR_WOLFCRYPT_SHA3_256,
        MIXCTR_OPENSSL_BLAKE2S,
        MIXCTR_WOLFCRYPT_BLAKE2S,
        MIXCTR_BLAKE3_BLAKE3,
#elif SIZE_MACRO == 48
        // 384-bit block size
        MIXCTR_AESNI,
        MIXCTR_OPENSSL,
        MIXCTR_WOLFSSL,
#elif SIZE_MACRO == 64
        // 512-bit block size
        MIXCTR_OPENSSL_SHA3_512,
        MIXCTR_WOLFCRYPT_SHA3_512,
        MIXCTR_OPENSSL_BLAKE2B,
        MIXCTR_WOLFCRYPT_BLAKE2B,
#endif
#if SIZE_MACRO <= 48
        // 384-bit internal state
        MIXCTR_XKCP_XOODYAK,
#endif
#if SIZE_MACRO <= 128
        // 1600-bit internal state: r=1088, c=512
        MIXCTR_OPENSSL_SHAKE256,
        MIXCTR_WOLFCRYPT_SHAKE256,
        MIXCTR_XKCP_TURBOSHAKE_256,
#endif
#if SIZE_MACRO <= 160
        // 1600-bit internal state: r=1344, c=256
        MIXCTR_OPENSSL_SHAKE128,
        MIXCTR_WOLFCRYPT_SHAKE128,
        MIXCTR_XKCP_TURBOSHAKE_128,
        MIXCTR_XKCP_KANGAROOTWELVE,
#endif
};

// Obtains the corresponding MixCTR function given a certain AES implmmentation.
mixctrpass_impl_t get_mixctr_impl(mixctr_t mix_type);

// Get the mix name given its mix type.
char *get_mix_name(mixctr_t mix_type);

// Get the mix type given its name.
mixctr_t get_mix_type(char *name);

#endif
