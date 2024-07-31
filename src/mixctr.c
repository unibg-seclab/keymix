#include "mixctr.h"

#include "config.h"
#include "types.h"

#include <assert.h>
#include <openssl/evp.h>
#include <string.h>
#include <wmmintrin.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

// ------------------------------------------------------------ WolfSSL

int wolfssl(byte *in, byte *out, size_t size) {
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * SIZE_BLOCK);
                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);

                wc_AesSetKey(&aes, key, 2 * SIZE_BLOCK, NULL, AES_ENCRYPTION);

                for (uint8_t b = 0; b < BLOCKS_PER_MACRO; b++)
                        wc_AesEncryptDirect(&aes, out + b * SIZE_BLOCK, (byte *)(in + b));
        }

        wc_AesFree(&aes);
        return 0;
}

// ------------------------------------------------------------ OpenSSL

int openssl(byte *in, byte *out, size_t size) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_256_ecb(), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * SIZE_BLOCK);

                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, (byte *)in, SIZE_MACRO);
        }

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

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

int aesni(byte *in, byte *out, size_t size) {
        byte *last = in + size;
        __m128i key_schedule[15];

        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key         = in;
                uint128_t iv      = *(uint128_t *)(in + 2 * SIZE_BLOCK);
                uint128_t data[3] = {iv, iv + 1, iv + 2};

                aes_256_key_expansion(key, key_schedule);
                for (int b = 0; b < BLOCKS_PER_MACRO; b++) {
                        aes256_enc(key_schedule, (byte *)(data + b), out + b * SIZE_BLOCK);
                }
        }
        return 0;
}

// ------------------------------------------------------------ Generic mixctr code

inline mixctrpass_impl_t get_mixctr_impl(mixctr_t name) {
        switch (name) {
        case MIXCTR_WOLFSSL:
                return &wolfssl;
        case MIXCTR_OPENSSL:
                return &openssl;
        case MIXCTR_AESNI:
                return &aesni;
        default:
                return NULL;
        }
}
