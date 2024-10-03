#include "mix.h"

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

#include "config.h"
#include "kravette-wbc.h"
#include "log.h"
#include "types.h"
#include "utils.h"
#include "xoofff-wbc.h"

// AES block size (128 bit)
#define AES_BLOCK_SIZE 16

// Number of AES execution in the MixCTR implementations
// NOTE: When using MixCTR the size of the MixCTR block should be
// BLOCK_SIZE = BLOCKS_PER_MACRO * AES_BLOCK_SIZE
#define BLOCKS_PER_MACRO 3

// *** OpenSSL hacks ***

// For performance reasons the OpenSSL doc suggests to avoid fetching the same
// cipher and digest algorithm multiple times.
// https://docs.openssl.org/master/man7/ossl-guide-libcrypto-introduction/#performance

// The following functions are helpers to ensure this is the case.

// NOTE: These function are not thread safe, so they must be executed once by
// the main thread and only then be shared among the worker threads. This is
// why, despite being ugly, we call them in the get_mix_func.

EVP_CIPHER *openssl_cipher;

EVP_CIPHER* fetch_openssl_cipher(const char* cipher_name) {
        // Fetch OpenSSL cipher only when necessary
        if (!openssl_cipher || strcmp(EVP_CIPHER_get0_name(openssl_cipher), cipher_name)) {
                openssl_cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
        }

        return openssl_cipher;
}

EVP_MD *openssl_digest;

EVP_MD* fetch_openssl_digest(const char* digest_name) {
        // Fetch OpenSSL digest only when necessary
        if (!openssl_digest || strcmp(EVP_MD_get0_name(openssl_digest), digest_name)) {
                openssl_digest = EVP_MD_fetch(NULL, digest_name, NULL);
        }

        return openssl_digest;
}

// *** MIXCTR FUNCTIONS ***

// --- WolfSSL ---

int wolfssl(byte *in, byte *out, size_t size) {
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * AES_BLOCK_SIZE);
                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == BLOCK_SIZE);

                wc_AesSetKey(&aes, key, 2 * AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);

                for (uint8_t b = 0; b < BLOCKS_PER_MACRO; b++)
                        wc_AesEncryptDirect(&aes, out + b * AES_BLOCK_SIZE, (byte *)(in + b));
        }

        wc_AesFree(&aes);
        return 0;
}

// --- OpenSSL ---

int openssl(byte *in, byte *out, size_t size) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, fetch_openssl_cipher("AES-256-ECB"), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * AES_BLOCK_SIZE);

                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == BLOCK_SIZE);
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, (byte *)in, BLOCK_SIZE);
        }

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        return 0;
}

// --- AES-NI as implemented by Intel ---

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

        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
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

// *** HASH FUNCTIONS ***

// --- OpenSSL hash functions ---

int generic_openssl_hash(byte *in, byte *out, size_t size, bool is_xof) {
        EVP_MD_CTX *mdctx;
        if ((mdctx = EVP_MD_CTX_create()) == NULL) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }
        if (!EVP_DigestInit_ex(mdctx, openssl_digest, NULL)) {
                _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                if (!EVP_DigestInit_ex(mdctx, NULL, NULL)) {
                       _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
                }
                if (!EVP_DigestUpdate(mdctx, in, BLOCK_SIZE)) {
                        _log(LOG_ERROR, "EVP_DigestUpdate error\n");
                }
                if (is_xof) {
                        if (!EVP_DigestFinalXOF(mdctx, out, BLOCK_SIZE)) {
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

int openssl_davies_meyer(byte *in, byte *out, size_t size) {
        unsigned char *iv = "cur-hardcoded-iv";
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, fetch_openssl_cipher("AES-128-ECB"), NULL, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                if (!EVP_EncryptInit(ctx, NULL, in, NULL)) {
                        _log(LOG_ERROR, "EVP_EncryptInit error\n");
                }
                if (!EVP_EncryptUpdate(ctx, out, &outl, iv, BLOCK_SIZE)) {
                        _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
                }
                memxor(out, out, iv, BLOCK_SIZE);
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
        unsigned char *iv = "cur-hardcoded-iv";
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, openssl_cipher, iv, NULL)) {
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

// --- wolfCrypt hash functions ---

int generic_wolfcrypt_hash(enum wc_HashType hash_type, byte *in, byte *out, size_t size) {
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                int error = wc_Hash(hash_type, in, BLOCK_SIZE, out, BLOCK_SIZE);
                if (error) {
                        _log(LOG_ERROR, "wc_Hash error %d\n", error);
                }
        }
        return 0;
}

int wolfcrypt_sha3_256_hash(byte *in, byte *out, size_t size) {
        return generic_wolfcrypt_hash(WC_HASH_TYPE_SHA3_256, in, out, size);
}

int wolfcrypt_sha3_512_hash(byte *in, byte *out, size_t size) {
        return generic_wolfcrypt_hash(WC_HASH_TYPE_SHA3_512, in, out, size);
}

int wolfcrypt_shake128_hash(byte *in, byte *out, size_t size) {
        wc_Shake shake[1];
        int ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_InitShake128 error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                int ret = wc_Shake128_Update(shake, in, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake128_Update error %d\n", ret);
                }
                ret = wc_Shake128_Final(shake, out, BLOCK_SIZE);
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
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                int ret = wc_Shake256_Update(shake, in, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Update error %d\n", ret);
                }
                ret = wc_Shake256_Final(shake, out, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Final error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2s_hash(byte *in, byte *out, size_t size) {
        int ret;
        Blake2s b2s;
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                ret = wc_InitBlake2s(&b2s, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_InitBlake2s error %d\n", ret);
                }
                ret = wc_Blake2sUpdate(&b2s, in, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sUpdate error %d\n", ret);
                }
                ret = wc_Blake2sFinal(&b2s, out, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2b_hash(byte *in, byte *out, size_t size) {
        int ret;
        Blake2b b2b;
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                ret = wc_InitBlake2b(&b2b, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_InitBlake2b error %d\n", ret);
                }
                ret = wc_Blake2bUpdate(&b2b, in, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bUpdate error %d\n", ret);
                }
                ret = wc_Blake2bFinal(&b2b, out, BLOCK_SIZE);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_davies_meyer(byte *in, byte *out, size_t size) {
        int ret;
        Aes aes;
        byte *iv = "cur-hardcoded-iv";

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                ret = wc_AesSetKey(&aes, in, AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesSetKey error\n");
                }
                ret = wc_AesEncryptDirect(&aes, out, iv);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out, iv, BLOCK_SIZE);
        }

        wc_AesFree(&aes);
        return 0;
}

int wolfcrypt_matyas_meyer_oseas(byte *in, byte *out, size_t size) {
        int ret;
        Aes aes;
        // To support inplace execution of the function we need avoid
        // overwriting the input
        bool is_inplace = (in == out);
        byte *out_enc = (is_inplace ? malloc(BLOCK_SIZE) : out);
        byte *iv = "cur-hardcoded-iv";

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        ret = wc_AesSetKey(&aes, iv, AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
        if (ret) {
                _log(LOG_ERROR, "wc_AesSetKey error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                ret = wc_AesEncryptDirect(&aes, out_enc, in);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out_enc, in, BLOCK_SIZE);

                if (!is_inplace) {
                        out_enc += BLOCK_SIZE;
                }
        }

        wc_AesFree(&aes);
        if (is_inplace) {
                free(out_enc);
        }
        return 0;
}

// --- XKCP hash functions ---

// Keccak-p[1600, 12]: Keccak 1600-bit permutations and 12 rounds

int xkcp_generic_turboshake_hash(uint32_t capacity, byte *in, byte *out, size_t size) {
        // choose a domain separation in the range `[0x01, 0x02, .. , 0x7F]`
        byte domain = 0x1F;

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                int result = TurboSHAKE(capacity, in, BLOCK_SIZE, domain, out, BLOCK_SIZE);
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
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                int result = KangarooTwelve(in, BLOCK_SIZE, out, BLOCK_SIZE, NULL, 0);
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
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);
                Xoodyak_Absorb(&instance, in, BLOCK_SIZE);
                Xoodyak_Squeeze(&instance, out, BLOCK_SIZE);
        }
        return 0;
}

// --- BLAKE3 hash function ---

int blake3_blake3_hash(byte *in, byte *out, size_t size) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                blake3_hasher_update(&hasher, in, BLOCK_SIZE);
                blake3_hasher_finalize(&hasher, out, BLOCK_SIZE);
                blake3_hasher_reset(&hasher);
        }
        return 0;
}

// *** SYMMETRIC CIPHER FUNCTIONS ***

// --- OpenSSL AES in ECB mode ---
int openssl_aes_ecb(byte *in, byte *out, size_t size) {
        const unsigned char *key = "super-secure-key";
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, fetch_openssl_cipher("AES-128-ECB"), key, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        if (!EVP_EncryptUpdate(ctx, out, &outl, in, size)) {
                _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
        }

        // if (!EVP_EncryptFinal(ctx, out, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        EVP_CIPHER_CTX_free(ctx);
        return 0;
}

// --- wolfCrypt AES in ECB mode ---
int wolfcrypt_aes_ecb(byte *in, byte *out, size_t size) {
        int ret;
        Aes aes;
        const byte *key = "super-secure-key";

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
        if (ret) {
                _log(LOG_ERROR, "wc_AesSetKey error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE, out += BLOCK_SIZE) {
                ret = wc_AesEncryptDirect(&aes, out, in);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
        }

        wc_AesFree(&aes);
        return 0;
}

// NOTE: Conflicting enum naming force us to implement Kravatte-WBC and
// Xoofff-WBC in separate files

// *** GET IMPLEMENTATION BY NAME ***

inline mix_func_t get_mix_func(mix_t mix_type) {
        switch (mix_type) {
#if BLOCK_SIZE == 16
        case OPENSSL_AES_128:
                fetch_openssl_cipher("AES-128-ECB");
                return &openssl_aes_ecb;
        case OPENSSL_DAVIES_MEYER_128:
                fetch_openssl_cipher("AES-128-ECB");
                return &openssl_davies_meyer;
        case OPENSSL_MATYAS_MEYER_OSEAS_128:
                fetch_openssl_cipher("AES-128-ECB");
                return &openssl_matyas_meyer_oseas;
        case WOLFCRYPT_AES_128:
                return &wolfcrypt_aes_ecb;
        case WOLFCRYPT_DAVIES_MEYER_128:
                return &wolfcrypt_davies_meyer;
        case WOLFCRYPT_MATYAS_MEYER_OSEAS_128:
                return &wolfcrypt_matyas_meyer_oseas;
#elif BLOCK_SIZE == 32
        case OPENSSL_SHA3_256:
                fetch_openssl_digest("SHA3-256");
                return &openssl_hash;
        case OPENSSL_BLAKE2S:
                fetch_openssl_digest("BLAKE2S-256");
                return &openssl_hash;
        case WOLFCRYPT_SHA3_256:
                return &wolfcrypt_sha3_256_hash;
        case WOLFCRYPT_BLAKE2S:
                return &wolfcrypt_blake2s_hash;
        case BLAKE3_BLAKE3:
                return &blake3_blake3_hash;
#elif BLOCK_SIZE == 48
        case WOLFSSL_MIXCTR:
                return &wolfssl;
        case OPENSSL_MIXCTR:
                fetch_openssl_cipher("AES-256-ECB");
                return &openssl;
        case AESNI_MIXCTR:
                return &aesni;
#elif BLOCK_SIZE == 64
        case OPENSSL_SHA3_512:
                fetch_openssl_digest("SHA3-512");
                return &openssl_hash;
        case OPENSSL_BLAKE2B:
                fetch_openssl_digest("BLAKE2B-512");
                return &openssl_hash;
        case WOLFCRYPT_SHA3_512:
                return &wolfcrypt_sha3_512_hash;
        case WOLFCRYPT_BLAKE2B:
                return &wolfcrypt_blake2b_hash;
#endif
#if BLOCK_SIZE <= 48
        // 384-bit internal state
        case XKCP_XOODYAK:
                return &xkcp_xoodyak_hash;
        case XKCP_XOOFFF_WBC:
                return &xkcp_xoofff_wbc_ecb;
#endif
#if BLOCK_SIZE <= 128
        // 1600-bit internal state: r=1088, c=512
        case OPENSSL_SHAKE256:
                fetch_openssl_digest("SHAKE-256");
                return &openssl_xof_hash;
        case WOLFCRYPT_SHAKE256:
                return &wolfcrypt_shake256_hash;
        case XKCP_TURBOSHAKE_256:
                return &xkcp_turboshake256_hash;
#endif
#if BLOCK_SIZE <= 160
        // 1600-bit internal state: r=1344, c=256
        case OPENSSL_SHAKE128:
                fetch_openssl_digest("SHAKE-128");
                return &openssl_xof_hash;
        case WOLFCRYPT_SHAKE128:
                return &wolfcrypt_shake128_hash;
        case XKCP_TURBOSHAKE_128:
                return &xkcp_turboshake128_hash;
        case XKCP_KANGAROOTWELVE:
                return &xkcp_kangarootwelve_hash;
#endif
#if BLOCK_SIZE <= 192
        // 1600-bit internal state
        case XKCP_KRAVETTE_WBC:
                return &xkcp_kravette_wbc_ecb;
#endif
        default:
                return NULL;
        }
}

char *MIX_NAMES[] = {
#if BLOCK_SIZE == 16
        // 128-bit block size
        "openssl-aes-128",
        "openssl-davies-meyer",
        "openssl-matyas-meyer-oseas",
        "wolfcrypt-aes-128",
        "wolfcrypt-davies-meyer",
        "wolfcrypt-matyas-meyer-oseas",
#elif BLOCK_SIZE == 32
        // 256-bit block size
        "openssl-sha3-256",
        "openssl-blake2s",
        "wolfcrypt-sha3-256",
        "wolfcrypt-blake2s",
        "blake3-blake3",
#elif BLOCK_SIZE == 48
        // 384-bit block size
        "aes-ni-mixctr",
        "openssl-mixctr",
        "wolfcrypt-mixctr",
#elif BLOCK_SIZE == 64
        // 512-bit block size
        "openssl-sha3-512",
        "openssl-blake2b",
        "wolfcrypt-sha3-512",
        "wolfcrypt-blake2b",
#endif
#if BLOCK_SIZE <= 48
        // 384-bit internal state
        "xkcp-xoodyak",
        "xkcp-xoofff-wbc",
#endif
#if BLOCK_SIZE <= 128
        // 1600-bit internal state: r=1088, c=512
        "openssl-shake256",
        "wolfcrypt-shake256",
        "xkcp-turboshake256",
#endif
#if BLOCK_SIZE <= 160
        // 1600-bit internal state: r=1344, c=256
        "openssl-shake128",
        "wolfcrypt-shake128",
        "xkcp-turboshake128",
        "xkcp-kangarootwelve",
#endif
#if BLOCK_SIZE <= 192
        // 1600-bit internal state
        "xkcp-kravette-wbc",
#endif
};

char *get_mix_name(mix_t mix_type) {
        return MIX_NAMES[mix_type];
}

mix_t get_mix_type(char* name) {
        for (int8_t i = 0; i < sizeof(MIX_NAMES) / sizeof(*MIX_NAMES); i++)
                if (strcmp(name, MIX_NAMES[i]) == 0)
                        return (mix_t)i;
        return -1;
}
