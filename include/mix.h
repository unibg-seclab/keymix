#ifndef MIX_H
#define MIX_H

#include "types.h"

#include <stdlib.h>

// Number of AES execution in the MixCTR implementations
#define BLOCKS_PER_MACRO 3

// Accepted types of mix implementations.
typedef enum {
        // Fixed-output functions
        // 128-bit block size
        OPENSSL_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        WOLFCRYPT_AES_128,
        WOLFCRYPT_DAVIES_MEYER_128,
        WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
        // 256-bit block size
        OPENSSL_SHA3_256,
        OPENSSL_BLAKE2S,
        WOLFCRYPT_SHA3_256,
        WOLFCRYPT_BLAKE2S,
        BLAKE3_BLAKE3,
        // 384-bit block size
        AESNI_MIXCTR,
        OPENSSL_MIXCTR,
        WOLFSSL_MIXCTR,
        // 512-bit block size
        OPENSSL_SHA3_512,
        OPENSSL_BLAKE2B,
        WOLFCRYPT_SHA3_512,
        WOLFCRYPT_BLAKE2B,
        // Extendable-output functions (XOFs)
        // 384-bit internal state
        XKCP_XOODYAK,
        // NOTE: To ensure a security strength of 128 bits, the block size
        // should be at least of 64 bytes. So, in our setup we can only reach
        // 96 bit of security (see https://eprint.iacr.org/2016/1188.pdf).
        XKCP_XOOFFF_WBC,
        // 1600-bit internal state: r=1088, c=512
        OPENSSL_SHAKE256,
        WOLFCRYPT_SHAKE256,
        XKCP_TURBOSHAKE_256,
        // 1600-bit internal state: r=1344, c=256
        OPENSSL_SHAKE128,
        WOLFCRYPT_SHAKE128,
        XKCP_TURBOSHAKE_128,
        XKCP_KANGAROOTWELVE,
        // 1600-bit internal state
        XKCP_KRAVETTE_WBC,
} mix_t;

typedef enum {
        // Fixed-output functions
        // We are bound to pick a block size equivalent to size of the output
        AES_BLOCK_SIZE_ = 16,
        SHA3_256_BLOCK_SIZE = 32,
        BLAKE2S_BLOCK_SIZE = 32,
        BLAKE3_BLOCK_SIZE = 32,
        MIXCTR_BLOCK_SIZE = 48,
        SHA3_512_BLOCK_SIZE = 64,
        BLAKE2B_BLOCK_SIZE = 64,
        // Extendable-output functions (XOFs)
        // We pick the biggest block size that does not exceed the internal
        // state of the permutation function and brings the best performance
        XOODYAK_BLOCK_SIZE = BLOCKS_PER_MACRO * AES_BLOCK_SIZE_, // 384-bit internal state
        XOOFFF_WBC_BLOCK_SIZE = 48, // 384-bit internal state
        SHAKE256_BLOCK_SIZE = 128, // 1600-bit internal state: r=1088, c=512
        TURBOSHAKE256_BLOCK_SIZE = 128, // 1600-bit internal state: r=1088, c=512
        SHAKE128_BLOCK_SIZE = 160, // 1600-bit internal state: r=1344, c=256
        TURBOSHAKE128_BLOCK_SIZE = 160, // 1600-bit internal state: r=1344, c=256
        KANGAROOTWELVE_BLOCK_SIZE = 160, // 1600-bit internal state: r=1344, c=256
        KRAVETTE_WBC_BLOCK_SIZE = 192, // 1600-bit internal state
} block_size_t;

const static mix_t MIX_TYPES[] = {
        // 128-bit block size
        OPENSSL_AES_128,
        WOLFCRYPT_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        WOLFCRYPT_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        WOLFCRYPT_MATYAS_MEYER_OSEAS_128,
        // 256-bit block size
        OPENSSL_SHA3_256,
        WOLFCRYPT_SHA3_256,
        OPENSSL_BLAKE2S,
        WOLFCRYPT_BLAKE2S,
        BLAKE3_BLAKE3,
        // 384-bit block size
        AESNI_MIXCTR,
        OPENSSL_MIXCTR,
        WOLFSSL_MIXCTR,
        // 384-bit internal state
        XKCP_XOODYAK,
        XKCP_XOOFFF_WBC,
        // 512-bit block size
        OPENSSL_SHA3_512,
        WOLFCRYPT_SHA3_512,
        OPENSSL_BLAKE2B,
        WOLFCRYPT_BLAKE2B,
        // 1600-bit internal state: r=1088, c=512
        OPENSSL_SHAKE256,
        WOLFCRYPT_SHAKE256,
        XKCP_TURBOSHAKE_256,
        // 1600-bit internal state: r=1344, c=256
        OPENSSL_SHAKE128,
        WOLFCRYPT_SHAKE128,
        XKCP_TURBOSHAKE_128,
        XKCP_KANGAROOTWELVE,
        // 1600-bit internal state
        XKCP_KRAVETTE_WBC,
};

const static block_size_t BLOCK_SIZES[] = {
        AES_BLOCK_SIZE_,
        SHA3_256_BLOCK_SIZE,
        MIXCTR_BLOCK_SIZE,
        SHA3_512_BLOCK_SIZE,
        SHAKE256_BLOCK_SIZE,
        SHAKE128_BLOCK_SIZE,
        KRAVETTE_WBC_BLOCK_SIZE,
};

// A function that implements mix on a series of blocks.
// Here `size` must be a multiple of `BLOCK_SIZE`.
typedef int (*mix_func_t)(byte *in, byte *out, size_t size);

// Get the mix function given its mix type.
int get_mix_func(mix_t mix_type, mix_func_t *func, block_size_t *block_size);

// Get the mix name given its mix type.
char *get_mix_name(mix_t mix_type);

// Get the mix type given its name.
mix_t get_mix_type(char *name);

#endif
