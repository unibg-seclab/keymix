#ifndef MIX_H
#define MIX_H

#include "types.h"

#include <stdlib.h>

// A function that implements mix on a series of blocks.
// Here `size` must be a multiple of `BLOCK_SIZE`.
typedef int (*mixpass_impl_t)(byte *in, byte *out, size_t size);

// Accepted types of mix implementations.
typedef enum {
        // Fixed-output functions
#if BLOCK_SIZE == 16
        OPENSSL_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        WOLFCRYPT_AES_128,
        WOLFCRYPT_DAVIES_MEYER_128,
        WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
#elif BLOCK_SIZE == 32
        // 256-bit block size
        OPENSSL_SHA3_256,
        OPENSSL_BLAKE2S,
        WOLFCRYPT_SHA3_256,
        WOLFCRYPT_BLAKE2S,
        BLAKE3_BLAKE3,
#elif BLOCK_SIZE == 48
        // 384-bit block size
        WOLFSSL_MIXCTR,
        OPENSSL_MIXCTR,
        AESNI_MIXCTR,
#elif BLOCK_SIZE == 64
        // 512-bit block size
        OPENSSL_SHA3_512,
        OPENSSL_BLAKE2B,
        WOLFCRYPT_SHA3_512,
        WOLFCRYPT_BLAKE2B,
#endif
        // Extendable-output functions (XOFs)
#if BLOCK_SIZE <= 48
        // 384-bit internal state
        XKCP_XOODYAK,
        // NOTE: To ensure a security strength of 128 bits, the block size
        // should be at least of 64 bytes. So, in our setup we can only reach
        // 96 bit of security (see https://eprint.iacr.org/2016/1188.pdf).
        XKCP_XOOFFF_WBC,
#endif
#if BLOCK_SIZE <= 128
        // 1600-bit internal state: r=1088, c=512
        // NOTE: To ensure the maximum security strength of 256 bits, the block
        // size should be at least of 64 bytes.
        OPENSSL_SHAKE256,
        WOLFCRYPT_SHAKE256,
        XKCP_TURBOSHAKE_256,
#endif
#if BLOCK_SIZE <= 160
        // 1600-bit internal state: r=1344, c=256
        // NOTE: To ensure the maximum security strength of 128 bits, the block
        // size should be at least of 32 bytes.
        OPENSSL_SHAKE128,
        WOLFCRYPT_SHAKE128,
        XKCP_TURBOSHAKE_128,
        XKCP_KANGAROOTWELVE,
#endif
#if BLOCK_SIZE <= 192
        // 1600-bit internal state
        // NOTE: To ensure the maximum security strength of 256 bits, the block
        // size should be at least of 64 bytes.
        XKCP_KRAVETTE_WBC,
#endif
} mix_t;

const static mix_t MIX_TYPES[] = {
#if BLOCK_SIZE == 16
        // 128-bit block size
        OPENSSL_AES_128,
        WOLFCRYPT_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        WOLFCRYPT_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
#elif BLOCK_SIZE == 32
        // 256-bit block size
        OPENSSL_SHA3_256,
        WOLFCRYPT_SHA3_256,
        OPENSSL_BLAKE2S,
        WOLFCRYPT_BLAKE2S,
        BLAKE3_BLAKE3,
#elif BLOCK_SIZE == 48
        // 384-bit block size
        AESNI_MIXCTR,
        OPENSSL_MIXCTR,
        WOLFSSL_MIXCTR,
#elif BLOCK_SIZE == 64
        // 512-bit block size
        OPENSSL_SHA3_512,
        WOLFCRYPT_SHA3_512,
        OPENSSL_BLAKE2B,
        WOLFCRYPT_BLAKE2B,
#endif
#if BLOCK_SIZE <= 48
        // 384-bit internal state
        XKCP_XOODYAK,
        XKCP_XOOFFF_WBC,
#endif
#if BLOCK_SIZE <= 128
        // 1600-bit internal state: r=1088, c=512
        OPENSSL_SHAKE256,
        WOLFCRYPT_SHAKE256,
        XKCP_TURBOSHAKE_256,
#endif
#if BLOCK_SIZE <= 160
        // 1600-bit internal state: r=1344, c=256
        OPENSSL_SHAKE128,
        WOLFCRYPT_SHAKE128,
        XKCP_TURBOSHAKE_128,
        XKCP_KANGAROOTWELVE,
#endif
#if BLOCK_SIZE <= 192
        // 1600-bit internal state
        XKCP_KRAVETTE_WBC,
#endif
};

// Obtains the corresponding MixCTR function given a certain AES implmmentation.
mixpass_impl_t get_mix_impl(mix_t mix_type);

// Get the mix name given its mix type.
char *get_mix_name(mix_t mix_type);

// Get the mix type given its name.
mix_t get_mix_type(char *name);

#endif
