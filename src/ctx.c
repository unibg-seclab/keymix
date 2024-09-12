#include "ctx.h"
#include "utils.h"
#include <assert.h>

#include <openssl/evp.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

// This is a little hack, because OpenSSL is *painfully* slow when used in
// multi-threaded environments.
// https://github.com/openssl/openssl/issues/17064
// This is defined in mixctr.c
extern EVP_CIPHER *openssl_aes256ecb;
extern const EVP_MD *openssl_hash_algorithm;
extern enum wc_HashType wolfcrypt_hash_algorithm;

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                      fanout_t fanout) {
        size_t num_macros = size / SIZE_MACRO;
        assert(size % SIZE_MACRO == 0 && ISPOWEROF(num_macros, fanout) &&
               "Number of 48-B blocks in the key should be a power of fanout");
        ctx->key        = key;
        ctx->key_size   = size;
        ctx->mixctr     = mixctr;
        ctx->mixctrpass = get_mixctr_impl(mixctr);
        ctx->fanout     = fanout;
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);

        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);

        switch (mixctr) {
        case MIXCTR_OPENSSL_SHA3_256:
        case MIXCTR_WOLFCRYPT_SHA3_256:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHA3-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHA3_256;
                break;
        case MIXCTR_OPENSSL_BLAKE2S_256:
        case MIXCTR_WOLFCRYPT_BLAKE2S_256:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_BLAKE2S;
                break;
        case MIXCTR_OPENSSL_SHA3_512:
        case MIXCTR_WOLFCRYPT_SHA3_512:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHA3-512", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHA3_512;
                break;
        case MIXCTR_OPENSSL_BLAKE2B_512:
        case MIXCTR_WOLFCRYPT_BLAKE2B_512:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "BLAKE2B-512", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_BLAKE2B;
                break;
        case MIXCTR_OPENSSL_SHAKE128_1536:
        case MIXCTR_WOLFCRYPT_SHAKE128_1536:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHAKE-128", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHAKE128;
                break;
        case MIXCTR_OPENSSL_SHAKE256_1536:
        case MIXCTR_WOLFCRYPT_SHAKE256_1536:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHAKE-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHAKE256;
                break;
        }
}

void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout) {
        size_t num_macros = size / SIZE_MACRO;
        assert(size % SIZE_MACRO == 0 && ISPOWEROF(num_macros, fanout) &&
               "Number of 48-B blocks in the key should be a power of fanout");
        ctx->key        = key;
        ctx->key_size   = size;
        ctx->mixctr     = mixctr;
        ctx->mixctrpass = get_mixctr_impl(mixctr);
        ctx->fanout     = fanout;
        ctx_disable_encryption(ctx);
        ctx_disable_iv_counter(ctx);

        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);

        switch (mixctr) {
        case MIXCTR_OPENSSL_SHA3_256:
        case MIXCTR_WOLFCRYPT_SHA3_256:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHA3-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHA3_256;
                break;
        case MIXCTR_OPENSSL_BLAKE2S_256:
        case MIXCTR_WOLFCRYPT_BLAKE2S_256:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_BLAKE2S;
                break;
        case MIXCTR_OPENSSL_SHA3_512:
        case MIXCTR_WOLFCRYPT_SHA3_512:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHA3-512", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHA3_512;
                break;
        case MIXCTR_OPENSSL_BLAKE2B_512:
        case MIXCTR_WOLFCRYPT_BLAKE2B_512:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "BLAKE2B-512", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_BLAKE2B;
                break;
        case MIXCTR_OPENSSL_SHAKE128_1536:
        case MIXCTR_WOLFCRYPT_SHAKE128_1536:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHAKE-128", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHAKE128;
                break;
        case MIXCTR_OPENSSL_SHAKE256_1536:
        case MIXCTR_WOLFCRYPT_SHAKE256_1536:
                openssl_hash_algorithm = EVP_MD_fetch(NULL, "SHAKE-256", NULL);
                wolfcrypt_hash_algorithm = WC_HASH_TYPE_SHAKE256;
                break;
        }
}

inline void ctx_enable_encryption(keymix_ctx_t *ctx) { ctx->encrypt = true; }

inline void ctx_disable_encryption(keymix_ctx_t *ctx) { ctx->encrypt = false; }

inline void ctx_enable_iv_counter(keymix_ctx_t *ctx, uint128_t iv) {
        ctx->do_iv_counter = true;
        ctx->iv            = iv;
}
inline void ctx_disable_iv_counter(keymix_ctx_t *ctx) {
        ctx->do_iv_counter = false;
        ctx->iv            = 0;
}
