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

// Maximum size of the OpenSSL encryption batch multiple of the AES block size
#define MAX_BATCH_SIZE 2147483520

// *** SYMMETRIC CIPHER FUNCTIONS ***

// --- OpenSSL AES in ECB mode ---
int openssl_aes_ecb(byte *in, byte *out, size_t size, byte *iv) {
        size_t remaining_size;
        size_t curr_size;
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, EVP_aes_128_ecb(), iv, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        // EVP_EncryptUpdate works up to sizes of 2^31 - 1. Bigger keys require
        // to call the function multiple times.
        remaining_size = size;
        while (remaining_size) {
                curr_size = MIN(remaining_size, MAX_BATCH_SIZE);
                if (!EVP_EncryptUpdate(ctx, out, &outl, in, curr_size)) {
                        _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
                }
                remaining_size -= curr_size;
        }

        // if (!EVP_EncryptFinal(ctx, out, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        EVP_CIPHER_CTX_free(ctx);
        return 0;
}

// --- wolfCrypt AES in ECB mode ---
int wolfcrypt_aes_ecb(byte *in, byte *out, size_t size, byte *iv) {
        int ret;
        Aes aes;

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        ret = wc_AesSetKey(&aes, iv, BLOCK_SIZE_AES, NULL, AES_ENCRYPTION);
        if (ret) {
                _log(LOG_ERROR, "wc_AesSetKey error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_AES, out += BLOCK_SIZE_AES) {
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

// *** MIXCTR FUNCTIONS ***

// --- WolfSSL ---

int wolfssl(byte *in, byte *out, size_t size, byte *iv) {
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_MIXCTR, out += BLOCK_SIZE_MIXCTR) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * BLOCK_SIZE_AES);
                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == BLOCK_SIZE_MIXCTR);

                wc_AesSetKey(&aes, key, 2 * BLOCK_SIZE_AES, NULL, AES_ENCRYPTION);

                for (uint8_t b = 0; b < BLOCKS_PER_MACRO; b++)
                        wc_AesEncryptDirect(&aes, out + b * BLOCK_SIZE_AES, (byte *)(in + b));
        }

        wc_AesFree(&aes);
        return 0;
}

// --- OpenSSL ---

int openssl(byte *in, byte *out, size_t size, byte *iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_256_ecb(), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_MIXCTR, out += BLOCK_SIZE_MIXCTR) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * BLOCK_SIZE_AES);

                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == BLOCK_SIZE_MIXCTR);
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, (byte *)in, BLOCK_SIZE_MIXCTR);
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

int aesni(byte *in, byte *out, size_t size, byte *iv) {
        byte *last = in + size;
        __m128i key_schedule[15];

        for (; in < last; in += BLOCK_SIZE_MIXCTR, out += BLOCK_SIZE_MIXCTR) {
                byte *key      = in;
                uint128_t data = *(uint128_t *)(in + 2 * BLOCK_SIZE_AES);
                uint128_t in[] = {data, data + 1, data + 2};

                aes_256_key_expansion(key, key_schedule);
                for (int b = 0; b < BLOCKS_PER_MACRO; b++) {
                        aes256_enc(key_schedule, (byte *)(in + b), out + b * BLOCK_SIZE_AES);
                }
        }
        return 0;
}

// *** HASH FUNCTIONS ***

// --- OpenSSL hash functions ---

int generic_openssl_hash(const EVP_MD *digest, block_size_t block_size,
                         byte *in, byte *out, size_t size, bool is_xof) {
        EVP_MD_CTX *mdctx;
        if ((mdctx = EVP_MD_CTX_create()) == NULL) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }
        if (!EVP_DigestInit_ex(mdctx, digest, NULL)) {
                _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
        }

        byte *last = in + size;
        for (; in < last; in += block_size, out += block_size) {
                if (!EVP_DigestInit_ex(mdctx, NULL, NULL)) {
                       _log(LOG_ERROR, "EVP_DigestInit_ex error\n");
                }
                if (!EVP_DigestUpdate(mdctx, in, block_size)) {
                        _log(LOG_ERROR, "EVP_DigestUpdate error\n");
                }
                if (is_xof) {
                        if (!EVP_DigestFinalXOF(mdctx, out, block_size)) {
                                _log(LOG_ERROR, "EVP_DigestFinalXOF error\n");
                        }
                } else {
                        if (!EVP_DigestFinal_ex(mdctx, out, NULL)) {
                                _log(LOG_ERROR, "EVP_DigestFinal_ex error\n");
                        }
                }
        }

        EVP_MD_CTX_free(mdctx);
        return 0;
}

int openssl_sha3_256_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_sha3_256();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_SHA3_256, in, out, size, false);
        return err;
}

int openssl_sha3_512_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_sha3_512();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_SHA3_512, in, out, size, false);
        return err;
}

int openssl_shake128_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_shake128();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_SHAKE128, in, out, size, true);
        return err;
}

int openssl_shake256_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_shake256();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_SHAKE256, in, out, size, true);
        return err;
}

int openssl_blake2s_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_blake2s256();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_BLAKE2S, in, out, size, false);
        return err;
}

int openssl_blake2b_hash(byte *in, byte *out, size_t size, byte *iv) {
        const EVP_MD *digest = EVP_blake2b512();
        int err = generic_openssl_hash(digest, BLOCK_SIZE_BLAKE2B, in, out, size, false);
        return err;
}

int openssl_davies_meyer(byte *in, byte *out, size_t size, byte *iv) {
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        if (!EVP_EncryptInit(ctx, EVP_aes_128_ecb(), NULL, NULL)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_AES, out += BLOCK_SIZE_AES) {
                if (!EVP_EncryptInit(ctx, NULL, in, NULL)) {
                        _log(LOG_ERROR, "EVP_EncryptInit error\n");
                }
                if (!EVP_EncryptUpdate(ctx, out, &outl, iv, BLOCK_SIZE_AES)) {
                        _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
                }
                memxor(out, out, iv, BLOCK_SIZE_AES);
        }

        // if (!EVP_EncryptFinal(ctx, out, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        EVP_CIPHER_CTX_free(ctx);
        return 0;
}

int openssl_matyas_meyer_oseas(byte *in, byte *out, size_t size, byte *iv) {
        // To support inplace execution of the function we need avoid
        // overwriting the input
        unsigned char *out_enc = (in == out ? malloc(size) : out);
        openssl_aes_ecb(in, out_enc, size, iv);
        memxor(out, out_enc, in, size);
        if (in == out) {
                free(out_enc);
        }
        return 0;
}

// --- wolfCrypt hash functions ---

int generic_wolfcrypt_hash(enum wc_HashType hash_type, block_size_t block_size,
                           byte *in, byte *out, size_t size) {
        byte *last = in + size;
        for (; in < last; in += block_size, out += block_size) {
                int error = wc_Hash(hash_type, in, block_size, out, block_size);
                if (error) {
                        _log(LOG_ERROR, "wc_Hash error %d\n", error);
                }
        }
        return 0;
}

int wolfcrypt_sha3_256_hash(byte *in, byte *out, size_t size, byte *iv) {
        return generic_wolfcrypt_hash(WC_HASH_TYPE_SHA3_256, BLOCK_SIZE_SHA3_256, in, out, size);
}

int wolfcrypt_sha3_512_hash(byte *in, byte *out, size_t size, byte *iv) {
        return generic_wolfcrypt_hash(WC_HASH_TYPE_SHA3_512, BLOCK_SIZE_SHA3_512, in, out, size);
}

int wolfcrypt_shake128_hash(byte *in, byte *out, size_t size, byte *iv) {
        wc_Shake shake;
        int ret = wc_InitShake128(&shake, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_InitShake128 error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_SHAKE128, out += BLOCK_SIZE_SHAKE128) {
                int ret = wc_Shake128_Update(&shake, in, BLOCK_SIZE_SHAKE128);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake128_Update error %d\n", ret);
                }
                ret = wc_Shake128_Final(&shake, out, BLOCK_SIZE_SHAKE128);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake128_Final error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_shake256_hash(byte *in, byte *out, size_t size, byte *iv) {
        wc_Shake shake;
        int ret = wc_InitShake256(&shake, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_InitShake256 error %d\n", ret);
        }
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_SHAKE256, out += BLOCK_SIZE_SHAKE256) {
                int ret = wc_Shake256_Update(&shake, in, BLOCK_SIZE_SHAKE256);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Update error %d\n", ret);
                }
                ret = wc_Shake256_Final(&shake, out, BLOCK_SIZE_SHAKE256);
                if (ret) {
                        _log(LOG_ERROR, "wc_Shake256_Final error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2s_hash(byte *in, byte *out, size_t size, byte *iv) {
        int ret;
        Blake2s b2s;
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_BLAKE2S, out += BLOCK_SIZE_BLAKE2S) {
                ret = wc_InitBlake2s(&b2s, BLOCK_SIZE_BLAKE2S);
                if (ret) {
                        _log(LOG_ERROR, "wc_InitBlake2s error %d\n", ret);
                }
                ret = wc_Blake2sUpdate(&b2s, in, BLOCK_SIZE_BLAKE2S);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sUpdate error %d\n", ret);
                }
                ret = wc_Blake2sFinal(&b2s, out, BLOCK_SIZE_BLAKE2S);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2sFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_blake2b_hash(byte *in, byte *out, size_t size, byte *iv) {
        int ret;
        Blake2b b2b;
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_BLAKE2B, out += BLOCK_SIZE_BLAKE2B) {
                ret = wc_InitBlake2b(&b2b, BLOCK_SIZE_BLAKE2B);
                if (ret) {
                        _log(LOG_ERROR, "wc_InitBlake2b error %d\n", ret);
                }
                ret = wc_Blake2bUpdate(&b2b, in, BLOCK_SIZE_BLAKE2B);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bUpdate error %d\n", ret);
                }
                ret = wc_Blake2bFinal(&b2b, out, BLOCK_SIZE_BLAKE2B);
                if (ret) {
                        _log(LOG_ERROR, "wc_Blake2bFinal error %d\n", ret);
                }
        }
        return 0;
}

int wolfcrypt_davies_meyer(byte *in, byte *out, size_t size, byte *iv) {
        int ret;
        Aes aes;

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_AES, out += BLOCK_SIZE_AES) {
                ret = wc_AesSetKey(&aes, in, BLOCK_SIZE_AES, NULL, AES_ENCRYPTION);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesSetKey error\n");
                }
                ret = wc_AesEncryptDirect(&aes, out, iv);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out, iv, BLOCK_SIZE_AES);
        }

        wc_AesFree(&aes);
        return 0;
}

int wolfcrypt_matyas_meyer_oseas(byte *in, byte *out, size_t size, byte *iv) {
        int ret;
        Aes aes;
        // To support inplace execution of the function we need avoid
        // overwriting the input
        bool is_inplace = (in == out);
        byte *out_enc = (is_inplace ? malloc(BLOCK_SIZE_AES) : out);

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret) {
                _log(LOG_ERROR, "wc_AesInit error\n");
        }

        ret = wc_AesSetKey(&aes, iv, BLOCK_SIZE_AES, NULL, AES_ENCRYPTION);
        if (ret) {
                _log(LOG_ERROR, "wc_AesSetKey error\n");
        }

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_AES, out += BLOCK_SIZE_AES) {
                ret = wc_AesEncryptDirect(&aes, out_enc, in);
                if (ret) {
                        _log(LOG_ERROR, "wc_AesEncryptDirect error\n");
                }
                memxor(out, out_enc, in, BLOCK_SIZE_AES);

                if (!is_inplace) {
                        out_enc += BLOCK_SIZE_AES;
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

int xkcp_generic_turboshake_hash(uint32_t capacity, block_size_t block_size,
                                 byte *in, byte *out, size_t size) {
        // choose a domain separation in the range `[0x01, 0x02, .. , 0x7F]`
        byte domain = 0x1F;

        byte *last = in + size;
        for (; in < last; in += block_size, out += block_size) {
                int result = TurboSHAKE(capacity, in, block_size, domain, out, block_size);
                if (result) {
                        _log(LOG_ERROR, "TurboSHAKE error %d\n", result);
                }
        }
        return 0;
}

int xkcp_turboshake128_hash(byte *in, byte *out, size_t size, byte *iv) {
        return xkcp_generic_turboshake_hash(256, BLOCK_SIZE_TURBOSHAKE128, in, out, size);
}

int xkcp_turboshake256_hash(byte *in, byte *out, size_t size, byte *iv) {
        return xkcp_generic_turboshake_hash(512, BLOCK_SIZE_TURBOSHAKE256, in, out, size);
}

int xkcp_kangarootwelve_hash(byte *in, byte *out, size_t size, byte *iv) {
        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_KANGAROOTWELVE, out += BLOCK_SIZE_KANGAROOTWELVE) {
                int result = KangarooTwelve(in, BLOCK_SIZE_KANGAROOTWELVE,
                                            out, BLOCK_SIZE_KANGAROOTWELVE,
                                            NULL, 0);
                if (result) {
                        _log(LOG_ERROR, "KangarooTwelve error %d\n", result);
                }
        }
        return 0;
}

// Xoodoo[12]: Xoodoo 384-bit permutations and 12 rounds

int xkcp_xoodyak_hash(byte *in, byte *out, size_t size, byte *iv) {
        Xoodyak_Instance instance;

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_XOODYAK, out += BLOCK_SIZE_XOODYAK) {
                Xoodyak_Initialize(&instance, NULL, 0, NULL, 0, NULL, 0);
                Xoodyak_Absorb(&instance, in, BLOCK_SIZE_XOODYAK);
                Xoodyak_Squeeze(&instance, out, BLOCK_SIZE_XOODYAK);
        }
        return 0;
}

// --- BLAKE3 hash function ---

int blake3_blake3_hash(byte *in, byte *out, size_t size, byte *iv) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        byte *last = in + size;
        for (; in < last; in += BLOCK_SIZE_BLAKE3, out += BLOCK_SIZE_BLAKE3) {
                blake3_hasher_update(&hasher, in, BLOCK_SIZE_BLAKE3);
                blake3_hasher_finalize(&hasher, out, BLOCK_SIZE_BLAKE3);
                blake3_hasher_reset(&hasher);
        }
        return 0;
}

// *** COMPLETE LIST OF MIX FUNCTIONS ***

mix_info_t MIX_FUNCTIONS[] = {
        // name, function, primitive, block size, one-way flag, iv support
        {"none", NULL, MIX_NONE, 0, true},
        {"openssl-aes-128", &openssl_aes_ecb, MIX_AES, BLOCK_SIZE_AES, false},
        {"openssl-davies-meyer", &openssl_davies_meyer, MIX_DAVIES_MEYER, BLOCK_SIZE_AES, true},
        {"openssl-matyas-meyer-oseas", &openssl_matyas_meyer_oseas, MIX_MATYAS_MEYER_OSEAS, BLOCK_SIZE_AES, true},
        {"wolfcrypt-aes-128", &wolfcrypt_aes_ecb, MIX_AES, BLOCK_SIZE_AES, false},
        {"wolfcrypt-davies-meyer", &wolfcrypt_davies_meyer, MIX_DAVIES_MEYER, BLOCK_SIZE_AES, true},
        {"wolfcrypt-matyas-meyer-oseas", &wolfcrypt_matyas_meyer_oseas, MIX_MATYAS_MEYER_OSEAS, BLOCK_SIZE_AES, true},
        {"openssl-sha3-256", &openssl_sha3_256_hash, MIX_SHA3_256, BLOCK_SIZE_SHA3_256, true},
        {"openssl-blake2s", &openssl_blake2s_hash, MIX_BLAKE2S, BLOCK_SIZE_BLAKE2S, true},
        {"wolfcrypt-sha3-256", &wolfcrypt_sha3_256_hash, MIX_SHA3_256, BLOCK_SIZE_SHA3_256, true},
        {"wolfcrypt-blake2s", &wolfcrypt_blake2s_hash, MIX_BLAKE2S, BLOCK_SIZE_BLAKE2S, true},
        {"blake3-blake3", &blake3_blake3_hash, MIX_BLAKE3, BLOCK_SIZE_BLAKE3, true},
        {"aes-ni-mixctr", &aesni, MIX_MIXCTR, BLOCK_SIZE_MIXCTR, true},
        {"openssl-mixctr", &openssl, MIX_MIXCTR, BLOCK_SIZE_MIXCTR, true},
        {"wolfcrypt-mixctr", &wolfssl, MIX_MIXCTR, BLOCK_SIZE_MIXCTR, true},
        {"openssl-sha3-512", &openssl_sha3_512_hash, MIX_SHA3_512, BLOCK_SIZE_SHA3_512, true},
        {"openssl-blake2b", &openssl_blake2b_hash, MIX_BLAKE2B, BLOCK_SIZE_BLAKE2B, true},
        {"wolfcrypt-sha3-512", &wolfcrypt_sha3_512_hash, MIX_SHA3_512, BLOCK_SIZE_SHA3_512, true},
        {"wolfcrypt-blake2b", &wolfcrypt_blake2b_hash, MIX_BLAKE2B, BLOCK_SIZE_BLAKE2B, true},
        {"xkcp-xoodyak", &xkcp_xoodyak_hash, MIX_XOODYAK, BLOCK_SIZE_XOODYAK, true},
        {"xkcp-xoofff-wbc", &xkcp_xoofff_wbc_ecb, MIX_XOOFFF_WBC, BLOCK_SIZE_XOOFFF_WBC, false},
        {"openssl-shake256", &openssl_shake256_hash, MIX_SHAKE256, BLOCK_SIZE_SHAKE256, true},
        {"wolfcrypt-shake256", &wolfcrypt_shake256_hash, MIX_SHAKE256, BLOCK_SIZE_SHAKE256, true},
        {"xkcp-turboshake256", &xkcp_turboshake256_hash, MIX_SHAKE256, BLOCK_SIZE_SHAKE256, true},
        {"openssl-shake128", &openssl_shake128_hash, MIX_SHAKE128, BLOCK_SIZE_SHAKE128, true},
        {"wolfcrypt-shake128", &wolfcrypt_shake128_hash, MIX_SHAKE128, BLOCK_SIZE_SHAKE128, true},
        {"xkcp-turboshake128", &xkcp_turboshake128_hash, MIX_TURBOSHAKE128, BLOCK_SIZE_TURBOSHAKE128, true},
        {"xkcp-kangarootwelve", &xkcp_kangarootwelve_hash, MIX_KANGAROOTWELVE, BLOCK_SIZE_KANGAROOTWELVE, true},
        {"xkcp-kravette-wbc", &xkcp_kravette_wbc_ecb, MIX_KRAVETTE_WBC, BLOCK_SIZE_KRAVETTE_WBC, false},
};

// *** GET IMPLEMENTATION BY NAME ***

int get_mix_func(mix_impl_t mix_type, mix_func_t *func, block_size_t *block_size) {
        uint8_t n = sizeof(MIX_FUNCTIONS) / sizeof(*MIX_FUNCTIONS);
        if (mix_type < 0 || mix_type >= n) {
                return 1;
        }

        *func = MIX_FUNCTIONS[mix_type].function;
        *block_size = MIX_FUNCTIONS[mix_type].block_size;
        return 0;
}

char *get_mix_name(mix_impl_t mix_type) {
        uint8_t n = sizeof(MIX_FUNCTIONS) / sizeof(*MIX_FUNCTIONS);
        if (mix_type < 0 || mix_type >= n) {
                return NULL;
        }

        return MIX_FUNCTIONS[mix_type].name;
}

mix_info_t *get_mix_info(mix_impl_t mix_type) {
        uint8_t n = sizeof(MIX_FUNCTIONS) / sizeof(*MIX_FUNCTIONS);
        if (mix_type < 0 || mix_type >= n) {
                return NULL;
        }

        return &MIX_FUNCTIONS[mix_type];
}

mix_impl_t get_mix_type(char* name) {
        uint8_t n = sizeof(MIX_FUNCTIONS) / sizeof(*MIX_FUNCTIONS);
        for (int8_t i = 0; i < n; i++)
                if (strcmp(name, MIX_FUNCTIONS[i].name) == 0)
                        return (mix_impl_t)i;
        return -1;
}

// *** RUN MIX FUNCTION WITH MULTIPLE THREADS ***

typedef struct {
        mix_func_t mixpass;
        byte *in;
        byte *out;
        size_t size;
        byte *iv;
} thr_mixpass_t;

void *w_thread_mixpass(void *a) {
        thr_mixpass_t *thr = (thr_mixpass_t*) a;
        (*thr->mixpass)(thr->in, thr->out, thr->size, thr->iv);
        return NULL;
}

int multi_threaded_mixpass(mix_func_t mixpass, block_size_t block_size,
                           byte *in, byte *out, size_t size, byte *iv,
                           uint8_t nof_threads) {
        int err = 0;
        pthread_t threads[nof_threads];
        thr_mixpass_t args[nof_threads];
        uint64_t tot_macros;
        uint64_t macros;
        size_t chunk_size;

        tot_macros = size / block_size;

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_mixpass_t *arg = args + t;

                macros     = get_curr_thread_size(tot_macros, t, nof_threads);
                chunk_size = block_size * macros;

                arg->mixpass = mixpass;
                arg->in      = in;
                arg->out     = out;
                arg->size    = chunk_size;
                arg->iv      = iv;

                pthread_create(&threads[t], NULL, w_thread_mixpass, arg);

                in += chunk_size;
                out += chunk_size;
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");
        for (uint8_t t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        _log(LOG_ERROR, "pthread_join error %d (thread %d)\n", err, t);
                        return err;
                }
        }

        return err;
}
