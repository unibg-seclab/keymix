#include "ctx.h"
#include "utils.h"
#include <assert.h>

#include <openssl/evp.h>

// This is a little hack, because OpenSSL is *painfully* slow when used in
// multi-threaded environments.
// https://github.com/openssl/openssl/issues/17064
// This is defined in mixctr.c
extern EVP_CIPHER *openssl_aes256ecb;

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                      fanout_t fanout) {
        size_t num_macros = size / SIZE_MACRO;
        assert(size % SIZE_MACRO == 0 && ISPOWEROF(num_macros, fanout) &&
               "Number of 48-B blocks in the key should be a power of fanout");
        ctx->key         = key;
        ctx->key_size    = size;
        ctx->mixctr_impl = get_mixctr_impl(mixctr);
        ctx->fanout      = fanout;
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);

        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);
}

void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout) {
        size_t num_macros = size / SIZE_MACRO;
        assert(size % SIZE_MACRO == 0 && ISPOWEROF(num_macros, fanout) &&
               "Number of 48-B blocks in the key should be a power of fanout");
        ctx->key         = key;
        ctx->key_size    = size;
        ctx->mixctr_impl = get_mixctr_impl(mixctr);
        ctx->fanout      = fanout;
        ctx_disable_encryption(ctx);
        ctx_disable_iv_counter(ctx);

        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);
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
