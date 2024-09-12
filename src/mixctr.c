#include "mixctr.h"

#include "config.h"
#include "log.h"
#include "types.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

#include <libXKCP/KangarooTwelve.h>
#include <openssl/evp.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>

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

EVP_CIPHER *openssl_aes256ecb;

int openssl(byte *in, byte *out, size_t size) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, openssl_aes256ecb, NULL, NULL);
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

// ------------------------------------------------------------ OpenSSL hash functions

EVP_MD *openssl_hash_algorithm;

int generic_openssl_hash(byte *in, byte *out, size_t size, bool is_xof) {
        EVP_MD_CTX *mdctx;
        if ((mdctx = EVP_MD_CTX_create()) == NULL) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }
        if (!EVP_DigestInit_ex(mdctx, openssl_hash_algorithm, NULL)) {
                _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
        }

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                if (!EVP_DigestInit_ex(mdctx, NULL, NULL)) {
                       _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
                }
                if (!EVP_DigestUpdate(mdctx, in, SIZE_MACRO)) {
                        _log(LOG_ERROR, "EVP_DigestUpdate error\n");
                }
                if (is_xof) {
                        if (!EVP_DigestFinalXOF(mdctx, out, SIZE_MACRO)) {
                                _log(LOG_ERROR, "EVP_DigestFinalXOF error\n");
                        }
                } else {
                        if (!EVP_DigestFinal_ex(mdctx, out, NULL)) {
                                _log(LOG_ERROR, "EVP_DigestFinal_ex error\n");
                        }
                }
        }

        EVP_MD_CTX_destroy(mdctx);
        return 0;
}

int openssl_hash(byte *in, byte *out, size_t size) {
        return generic_openssl_hash(in, out, size, false);
}

int openssl_xof_hash(byte *in, byte *out, size_t size) {
        return generic_openssl_hash(in, out, size, true);
}

// ------------------------------------------------------------ wolfCrypt hash functions

enum wc_HashType wolfcrypt_hash_algorithm;

int wolfcrypt_hash(byte *in, byte *out, size_t size) {
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int error = wc_Hash(wolfcrypt_hash_algorithm, in, SIZE_MACRO, out, SIZE_MACRO);
                if (error) {
                        _log(LOG_ERROR, "wc_Hash error %d\n", error);
                }
        }
        return 0;
}

int wolfcrypt_shake128_hash(byte *in, byte *out, size_t size) {
        wc_Shake shake[1];
        int ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_InitShake128 error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int ret = wc_Shake128_Update(shake, in, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake128_Update error %d\n", ret);
                }
                wc_Shake128_Final(shake, out, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake128_Final error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_shake256_hash(byte *in, byte *out, size_t size) {
        wc_Shake shake[1];
        int ret = wc_InitShake256(shake, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_InitShake256 error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int ret = wc_Shake256_Update(shake, in, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Update error %d\n", ret);
                }
                wc_Shake256_Final(shake, out, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Final error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2s_hash(byte *in, byte *out, size_t size) {
        Blake2s b2s[1];
        int ret = wc_InitBlake2s(b2s, SIZE_MACRO);
        if (ret) {
                _log(LOG_ERROR, "wc_InitBlake2s error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int ret = wc_Blake2sUpdate(b2s, in, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sUpdate error %d\n", ret);
                }
                wc_Blake2sFinal(b2s, out, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2b_hash(byte *in, byte *out, size_t size) {
        Blake2b b2b[1];
        int ret = wc_InitBlake2b(b2b, SIZE_MACRO);
        if (ret) {
                _log(LOG_ERROR, "wc_InitBlake2b error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int ret = wc_Blake2bUpdate(b2b, in, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bUpdate error %d\n", ret);
                }
                wc_Blake2bFinal(b2b, out, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bFinal error %d\n", ret);
                }
        }
        return 0;
}

// ------------------------------------------------------------ XKCP hash functions

int xkcp_generic_turboshake_hash(uint32_t capacity, byte *in, byte *out, size_t size) {
        // choose a domain separation in the range `[0x01, 0x02, .. , 0x7F]`
        byte domain = 0x1F;

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int result = TurboSHAKE(capacity, in, SIZE_MACRO, domain, out, SIZE_MACRO);
                if (result) {
                        _log(LOG_ERROR, "TurboSHAKE error %d\n", result);
                }
        }
        return 0;
}

int xkcp_turboshake128_hash(byte *in, byte *out, size_t size) {
        return xkcp_generic_turboshake_hash(128, in, out, size);
}

int xkcp_turboshake256_hash(byte *in, byte *out, size_t size) {
        return xkcp_generic_turboshake_hash(256, in, out, size);
}

int xkcp_kangarootwelve_hash(byte *in, byte *out, size_t size) {
        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                int result = KangarooTwelve(in, SIZE_MACRO, out, SIZE_MACRO, NULL, 0);
                if (result) {
                        _log(LOG_ERROR, "KangarooTwelve error %d\n", result);
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
        case MIXCTR_OPENSSL_SHA3_256:
        case MIXCTR_OPENSSL_BLAKE2S_256:
        case MIXCTR_OPENSSL_SHA3_512:
        case MIXCTR_OPENSSL_BLAKE2B_512:
                return &openssl_hash;
        case MIXCTR_OPENSSL_SHAKE128_1536:
        case MIXCTR_OPENSSL_SHAKE256_1536:
                return &openssl_xof_hash;
        case MIXCTR_WOLFCRYPT_SHA3_256:
        case MIXCTR_WOLFCRYPT_SHA3_512:
                return &wolfcrypt_hash;
        case MIXCTR_WOLFCRYPT_BLAKE2S_256:
                return &wolfcrypt_blake2s_hash;
        case MIXCTR_WOLFCRYPT_BLAKE2B_512:
                return &wolfcrypt_blake2b_hash;
        case MIXCTR_WOLFCRYPT_SHAKE128_1536:
                return &wolfcrypt_shake128_hash;
        case MIXCTR_WOLFCRYPT_SHAKE256_1536:
                return &wolfcrypt_shake256_hash;
        case MIXCTR_XKCP_TURBOSHAKE_128_256:
        case MIXCTR_XKCP_TURBOSHAKE_128_512:
        case MIXCTR_XKCP_TURBOSHAKE_128_1536:
                return &xkcp_turboshake128_hash;
        case MIXCTR_XKCP_TURBOSHAKE_256_256:
        case MIXCTR_XKCP_TURBOSHAKE_256_512:
        case MIXCTR_XKCP_TURBOSHAKE_256_1536:
                return &xkcp_turboshake256_hash;
        case MIXCTR_XKCP_KANGAROOTWELVE_256:
        case MIXCTR_XKCP_KANGAROOTWELVE_512:
        case MIXCTR_XKCP_KANGAROOTWELVE_1536:
                return &xkcp_kangarootwelve_hash;
        default:
                return NULL;
        }
}
