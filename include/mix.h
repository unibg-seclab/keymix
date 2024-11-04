#ifndef MIX_H
#define MIX_H

#include "types.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Number of AES execution in the MixCTR implementations
#define BLOCKS_PER_MACRO 3

// Accepted types of mix implementations.
typedef enum {
        NONE,
        // Fixed-output functions
        // 128-bit block size
        OPENSSL_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        OPENSSL_NEW_MATYAS_MEYER_OSEAS_128,
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
} mix_impl_t;

// A function that implements mix on a series of blocks.
// Here `size` must be a multiple of `BLOCK_SIZE`.
typedef int (*mix_func_t)(byte *in, byte *out, size_t size, byte *iv);

typedef enum {
        MIX_NONE,
        // Fixed-output functions
        // 128-bit block size
        MIX_AES,
        MIX_DAVIES_MEYER,
        MIX_MATYAS_MEYER_OSEAS,
        // 256-bit block size
        MIX_SHA3_256,
        MIX_BLAKE2S,
        MIX_BLAKE3,
        // 384-bit block size
        MIX_MIXCTR,
        // 512-bit block size
        MIX_SHA3_512,
        MIX_BLAKE2B,
        // Extendable-output functions (XOFs)
        // 384-bit internal state
        MIX_XOODYAK,
        MIX_XOOFFF_WBC,
        // 1600-bit internal state: r=1088, c=512
        MIX_SHAKE256,
        MIX_TURBOSHAKE256,
        // 1600-bit internal state: r=1344, c=256
        MIX_SHAKE128,
        MIX_TURBOSHAKE128,
        MIX_KANGAROOTWELVE,
        // 1600-bit internal state
        MIX_KRAVETTE_WBC,
} mix_t;

typedef enum {
        // Fixed-output functions
        // We are bound to pick a block size equivalent to size of the output
        BLOCK_SIZE_AES = 16,
        BLOCK_SIZE_SHA3_256 = 32,
        BLOCK_SIZE_BLAKE2S = 32,
        BLOCK_SIZE_BLAKE3 = 32,
        BLOCK_SIZE_MIXCTR = BLOCKS_PER_MACRO * BLOCK_SIZE_AES,
        BLOCK_SIZE_SHA3_512 = 64,
        BLOCK_SIZE_BLAKE2B = 64,
        // Extendable-output functions (XOFs)
        // We pick the biggest block size that does not exceed the internal
        // state of the permutation function and brings the best performance
        BLOCK_SIZE_XOODYAK = 48, // 384-bit internal state
        BLOCK_SIZE_XOOFFF_WBC = 48, // 384-bit internal state
        BLOCK_SIZE_SHAKE256 = 128, // 1600-bit internal state: r=1088, c=512
        BLOCK_SIZE_TURBOSHAKE256 = 128, // 1600-bit internal state: r=1088, c=512
        BLOCK_SIZE_SHAKE128 = 160, // 1600-bit internal state: r=1344, c=256
        BLOCK_SIZE_TURBOSHAKE128 = 160, // 1600-bit internal state: r=1344, c=256
        BLOCK_SIZE_KANGAROOTWELVE = 160, // 1600-bit internal state: r=1344, c=256
        BLOCK_SIZE_KRAVETTE_WBC = 192, // 1600-bit internal state
} block_size_t;

typedef struct {
        char *name;
        mix_func_t function;
        mix_t primitive;
        block_size_t block_size;
        bool is_one_way;
} mix_info_t;

const static mix_impl_t MIX_TYPES[] = {
        // 128-bit block size
        OPENSSL_AES_128,
        WOLFCRYPT_AES_128,
        OPENSSL_DAVIES_MEYER_128,
        WOLFCRYPT_DAVIES_MEYER_128,
        OPENSSL_MATYAS_MEYER_OSEAS_128,
        OPENSSL_NEW_MATYAS_MEYER_OSEAS_128,
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
        BLOCK_SIZE_AES,
        BLOCK_SIZE_SHA3_256,
        BLOCK_SIZE_MIXCTR,
        BLOCK_SIZE_SHA3_512,
        BLOCK_SIZE_SHAKE256,
        BLOCK_SIZE_SHAKE128,
        BLOCK_SIZE_KRAVETTE_WBC,
};

// Get the mix function given its mix type.
int get_mix_func(mix_impl_t mix_type, mix_func_t *func, block_size_t *block_size);

// Get the mix name given its mix type.
char *get_mix_name(mix_impl_t mix_type);

// Get mix info from the mix type.
mix_info_t *get_mix_info(mix_impl_t mix_type);

// Get the mix type given its name.
mix_impl_t get_mix_type(char *name);

// Run mix function with multiple threads.
int multi_threaded_mixpass(mix_func_t mixpass, block_size_t block_size,
                           byte *in, byte *out, size_t size, byte *iv,
                           uint8_t nof_threads);

#endif
