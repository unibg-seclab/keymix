#include "mixctr.h"

#include "config.h"
#include "log.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

#include <blake3/blake3.h>
#include <xkcp/KangarooTwelve.h>
#include <xkcp/Xoodyak.h>
#include <openssl/evp.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>

// AES block size (128 bit)
#define AES_BLOCK_SIZE 16

// Number of AES execution in the MixCTR implementations
// NOTE: When using MixCTR the size of the MixCTR block should be
// SIZE_MACRO = BLOCKS_PER_MACRO * AES_BLOCK_SIZE
#define BLOCKS_PER_MACRO 3

// ------------------------------------------------------------ WolfSSL

int wolfssl(byte *in, byte *out, size_t size) {
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * AES_BLOCK_SIZE);
                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);

                wc_AesSetKey(&aes, key, 2 * AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);

                for (uint8_t b = 0; b < BLOCKS_PER_MACRO; b++)
                        wc_AesEncryptDirect(&aes, out + b * AES_BLOCK_SIZE, (byte *)(in + b));
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
                uint128_t data = *(uint128_t *)(in + 2 * AES_BLOCK_SIZE);

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
                uint128_t iv      = *(uint128_t *)(in + 2 * AES_BLOCK_SIZE);
                uint128_t data[3] = {iv, iv + 1, iv + 2};

                aes_256_key_expansion(key, key_schedule);
                for (int b = 0; b < BLOCKS_PER_MACRO; b++) {
                        aes256_enc(key_schedule, (byte *)(data + b), out + b * AES_BLOCK_SIZE);
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

EVP_CIPHER *openssl_aes128ecb;

int openssl_davies_meyer(byte *in, byte *out, size_t size) {
        unsigned char *iv = "curr-hadcoded-iv";
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, openssl_aes128ecb, NULL, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                if (!EVP_EncryptInit(ctx, NULL, in, NULL)) {
                        _log(LOG_ERROR, "EVP_EncryptInit error\n");
                }
                if (!EVP_EncryptUpdate(ctx, out, &outl, iv, SIZE_MACRO)) {
                        _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
                }
                memxor(out, out, iv, SIZE_MACRO);
        }

        // if (!EVP_EncryptFinal(ctx, out, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        EVP_CIPHER_CTX_free(ctx);
        return 0;
}

int openssl_matyas_meyer_oseas(byte *in, byte *out, size_t size) {
        // To support inplace execution of the function we need avoid
        // overwriting the input
        unsigned char *out_enc = (in == out ? malloc(size) : out);
        unsigned char *iv = "curr-hadcoded-iv";
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, openssl_aes128ecb, iv, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        if (!EVP_EncryptUpdate(ctx, out_enc, &outl, in, size)) {
                _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
        }

        // if (!EVP_EncryptFinal(ctx, out_enc, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        memxor(out, out_enc, in, size);

        EVP_CIPHER_CTX_free(ctx);

        if (in == out) {
                free(out_enc);
        }
        return 0;
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
                ret = wc_Shake128_Final(shake, out, SIZE_MACRO);
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
                ret = wc_Shake256_Final(shake, out, SIZE_MACRO);
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
                ret = wc_Blake2sFinal(b2s, out, SIZE_MACRO);
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
                ret = wc_Blake2bFinal(b2b, out, SIZE_MACRO);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_davies_meyer(byte *in, byte *out, size_t size) {
        int ret;
        Aes aes;
        byte *iv = "curr-hadcoded-iv";

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                ret = wc_AesSetKey(&aes, in, AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesSetKey error\n");
                }
                ret = wc_AesEncryptDirect(&aes, out, iv);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out, iv, SIZE_MACRO);
        }

        wc_AesFree(&aes);
        return 0;
}

int wolfcrypt_matyas_meyer_oseas(byte *in, byte *out, size_t size) {
        int ret;
        Aes aes;
        // To support inplace execution of the function we need avoid
        // overwriting the input
        byte *out_enc = (in == out ? malloc(size) : out);
        byte *iv = "curr-hadcoded-iv";

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        ret = wc_AesSetKey(&aes, iv, AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
        if (ret) {
                _log(LOG_ERROR, "wc_AesSetKey error\n");
        }

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                ret = wc_AesEncryptDirect(&aes, out_enc, in);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out_enc, in, SIZE_MACRO);
        }

        wc_AesFree(&aes);
        if (in == out) {
                free(out_enc);
        }
        return 0;
}

// ------------------------------------------------------------ XKCP hash functions

// Keccak-p[1600, 12]: Keccak 1600-bit permutations and 12 rounds

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

// Xoodoo[12]: Xoodoo 384-bit permutations and 12 rounds
int xkcp_xoodyak_hash(byte *in, byte *out, size_t size) {
        Xoodyak_Instance instance;

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);
                Xoodyak_Absorb(&instance, in, SIZE_MACRO);
                Xoodyak_Squeeze(&instance, out, SIZE_MACRO);
        }
        return 0;
}

// ------------------------------------------------------------ BLAKE3 hash function

int blake3_blake3_hash(byte *in, byte *out, size_t size) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        byte *last = in + size;
        for (; in < last; in += SIZE_MACRO, out += SIZE_MACRO) {
                blake3_hasher_update(&hasher, in, SIZE_MACRO);
                blake3_hasher_finalize(&hasher, out, SIZE_MACRO);
                blake3_hasher_reset(&hasher);
        }
        return 0;
}

// ------------------------------------------------------------ Generic mixctr code

inline mixctrpass_impl_t get_mixctr_impl(mixctr_t mix_type) {
        switch (mix_type) {
#if SIZE_MACRO == 16
        case MIXCTR_OPENSSL_DAVIES_MEYER_128:
                return &openssl_davies_meyer;
        case MIXCTR_WOLFCRYPT_DAVIES_MEYER_128:
                return &wolfcrypt_davies_meyer;
        case MIXCTR_OPENSSL_MATYAS_MEYER_OSEAS_128:
                return &openssl_matyas_meyer_oseas;
        case MIXCTR_WOLFCRYPT_MATYAS_MEYER_OSEAS_128:
                return &wolfcrypt_matyas_meyer_oseas;
#elif SIZE_MACRO == 32
        case MIXCTR_OPENSSL_SHA3_256:
        case MIXCTR_OPENSSL_BLAKE2S:
                return &openssl_hash;
        case MIXCTR_WOLFCRYPT_SHA3_256:
                return &wolfcrypt_hash;
        case MIXCTR_WOLFCRYPT_BLAKE2S:
                return &wolfcrypt_blake2s_hash;
        case MIXCTR_BLAKE3_BLAKE3:
                return &blake3_blake3_hash;
#elif SIZE_MACRO == 48
        case MIXCTR_WOLFSSL:
                return &wolfssl;
        case MIXCTR_OPENSSL:
                return &openssl;
        case MIXCTR_AESNI:
                return &aesni;
#elif SIZE_MACRO == 64
        case MIXCTR_OPENSSL_SHA3_512:
        case MIXCTR_OPENSSL_BLAKE2B:
                return &openssl_hash;
        case MIXCTR_WOLFCRYPT_SHA3_512:
                return &wolfcrypt_hash;
        case MIXCTR_WOLFCRYPT_BLAKE2B:
                return &wolfcrypt_blake2b_hash;
#endif
#if SIZE_MACRO <= 48
        // 384-bit internal state
        case MIXCTR_XKCP_XOODYAK:
                return &xkcp_xoodyak_hash;
#endif
#if SIZE_MACRO <= 128
        // 1600-bit internal state: r=1088, c=512
        case MIXCTR_OPENSSL_SHAKE256:
                return &openssl_xof_hash;
        case MIXCTR_WOLFCRYPT_SHAKE256:
                return &wolfcrypt_shake256_hash;
        case MIXCTR_XKCP_TURBOSHAKE_256:
                return &xkcp_turboshake256_hash;
#endif
#if SIZE_MACRO <= 160
        // 1600-bit internal state: r=1344, c=256
        case MIXCTR_OPENSSL_SHAKE128:
                return &openssl_xof_hash;
        case MIXCTR_WOLFCRYPT_SHAKE128:
                return &wolfcrypt_shake128_hash;
        case MIXCTR_XKCP_TURBOSHAKE_128:
                return &xkcp_turboshake128_hash;
        case MIXCTR_XKCP_KANGAROOTWELVE:
                return &xkcp_kangarootwelve_hash;
#endif
        default:
                return NULL;
        }
}

char *MIX_NAMES[] = {
#if SIZE_MACRO == 16
        // 128-bit block size
        "openssl-davies-meyer",
        "wolfcrypt-davies-meyer",
        "openssl-matyas-meyer-oseas",
        "wolfcrypt-matyas-meyer-oseas",
#elif SIZE_MACRO == 32
        // 256-bit block size
        "openssl-sha3-256",
        "wolfcrypt-sha3-256",
        "openssl-blake2s",
        "wolfcrypt-blake2s",
        "blake3-blake3",
#elif SIZE_MACRO == 48
        // 384-bit block size
        "aes-ni-mixctr",
        "openssl-mixctr",
        "wolfcrypt-mixctr",
#elif SIZE_MACRO == 64
        // 512-bit block size
        "openssl-sha3-512",
        "wolfcrypt-sha3-512",
        "openssl-blake2b",
        "wolfcrypt-blake2b",
#endif
#if SIZE_MACRO <= 48 /* 384-bit internal state */
        "xkcp-xoodyak",
#endif
#if SIZE_MACRO <= 128
        // 1600-bit internal state: r=1088, c=512
        "openssl-shake256",
        "wolfcrypt-shake256",
        "xkcp-turboshake256",
#endif
#if SIZE_MACRO <= 160
        // 1600-bit internal state: r=1344, c=256
        "openssl-shake128",
        "wolfcrypt-shake128",
        "xkcp-turboshake128",
        "xkcp-kangarootwelve",
#endif
};

char *get_mix_name(mixctr_t mix_type) {
        return MIX_NAMES[mix_type];
}
