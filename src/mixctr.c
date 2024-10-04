#include "mixctr.h"

#include "types.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

// ------------------------------------------------------------ WolfSSL

int wolfssl(void *wolfssl_ctx, byte *key, uint128_t *data, size_t blocks_per_macro, byte *out) {
        wc_AesSetKey(wolfssl_ctx, key, 2 * SIZE_BLOCK, NULL, AES_ENCRYPTION);

        for (uint8_t b = 0; b < blocks_per_macro; b++)
                wc_AesEncryptDirect(wolfssl_ctx, out + b * SIZE_BLOCK, (byte *)(data + b));
        return 0;
}

// ------------------------------------------------------------ OpenSSL

int openssl(void *openssl_ctx, byte *key, uint128_t *data, size_t blocks_per_macro, byte *out) {
        int outl;
        EVP_EncryptInit(openssl_ctx, NULL, key, NULL);
        EVP_EncryptUpdate(openssl_ctx, out, &outl, (byte *)data, blocks_per_macro * SIZE_BLOCK);
        return 0;
}

// ------------------------------------------------------------ AES-NI as implemented by Intel

// Implemented following the Intel white paper here
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

__m128i key_256_assist_1(__m128i key1, __m128i m) {
        __m128i tmp;
        m = _mm_shuffle_epi32(m, 0xff);

        tmp  = _mm_slli_si128(key1, 0x4);
        key1 = _mm_xor_si128(key1, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        key1 = _mm_xor_si128(key1, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        key1 = _mm_xor_si128(key1, tmp);
        key1 = _mm_xor_si128(key1, m);
        return key1;
}

__m128i key_256_assist_2(__m128i key1, __m128i key2) {
        __m128i tmp = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key1, 0x0), 0xaa);
        __m128i m   = _mm_slli_si128(key2, 0x4);

        key2 = _mm_xor_si128(key2, m);

        m    = _mm_slli_si128(m, 0x4);
        key2 = _mm_xor_si128(key2, m);

        m    = _mm_slli_si128(m, 0x4);
        key2 = _mm_xor_si128(key2, m);
        key2 = _mm_xor_si128(key2, tmp);

        return key2;
}

void aes_256_key_expansion(byte *key, __m128i *key_schedule) {
#define KEYROUND_1(i, rcon)                                                                        \
        key_schedule[i] = key_256_assist_1(key_schedule[i - 2],                                    \
                                           _mm_aeskeygenassist_si128(key_schedule[i - 1], rcon))
#define KEYROUND_2(i) key_schedule[i] = key_256_assist_2(key_schedule[i - 1], key_schedule[i - 2])

        key_schedule[0] = _mm_loadu_si128((__m128i *)key);
        key_schedule[1] = _mm_loadu_si128((__m128i *)(key + 16));

        KEYROUND_1(2, 0x01);
        KEYROUND_2(3);
        KEYROUND_1(4, 0x02);
        KEYROUND_2(5);
        KEYROUND_1(6, 0x04);
        KEYROUND_2(7);
        KEYROUND_1(8, 0x08);
        KEYROUND_2(9);
        KEYROUND_1(10, 0x10);
        KEYROUND_2(11);
        KEYROUND_1(12, 0x20);
        KEYROUND_2(13);
        KEYROUND_1(14, 0x40);

#undef KEYROUND_1
#undef KEYROUND_2
}

void aes256_enc(__m128i *key_schedule, byte *data, byte *out) {
        __m128i m;
        uint8_t j;

        m = _mm_loadu_si128((__m128i *)data);
        m = _mm_xor_si128(m, key_schedule[0]);

        for (j = 1; j < 14; j++) {
                m = _mm_aesenc_si128(m, key_schedule[j]);
        }
        m = _mm_aesenclast_si128(m, key_schedule[j]);
        _mm_storeu_si128((__m128i *)out, m);
}

int aesni(void *_ignored, byte *key, uint128_t *data, size_t blocks_per_macro, byte *out) {
        __m128i key_schedule[15];

        aes_256_key_expansion(key, key_schedule);
        for (int b = 0; b < blocks_per_macro; b++) {
                aes256_enc(key_schedule, (byte *)(data + b), out + b * SIZE_BLOCK);
        }

        return 0;
}

// ------------------------------------------------------------ Generic mixctr code

inline int get_mixctr_impl(mixctr_t name, mixctr_impl_t *impl, size_t *size_macro) {
        *size_macro = 48;

        switch (name) {
        case MIXCTR_WOLFSSL:
                *impl = &wolfssl;
                return 0;
        case MIXCTR_OPENSSL:
                *impl = &openssl;
                return 0;
        case MIXCTR_AESNI:
                *impl = &aesni;
                return 0;
        default:
                *impl       = NULL;
                *size_macro = 0;
                return 1;
        }
}
