#include "ctx.h"
#include "utils.h"
#include <assert.h>

#include <openssl/evp.h>

// This is a little hack, because OpenSSL is *painfully* slow when used in
// multi-threaded environments.
// https://github.com/openssl/openssl/issues/17064
// This is defined in mixctr.c
extern EVP_CIPHER *openssl_aes256ecb;

int ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                     fanout_t fanout) {
        int err = ctx_keymix_init(ctx, mixctr, key, size, fanout);
        if (err)
                return err;
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);
        return 0;
}

int ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout) {
        int err = 0;
        if (get_mixctr_impl(mixctr, &ctx->mixctr_impl, &ctx->size_macro)) {
                err = CTX_ERR_NOMIXCTR;
        }

        size_t num_macros = size / ctx->size_macro;
        if (size % ctx->size_macro != 0 || !ISPOWEROF(num_macros, fanout)) {
                err = CTX_ERR_KEYSIZE;
        }
        ctx->key      = key;
        ctx->key_size = size;
        ctx->fanout   = fanout;
        ctx_disable_encryption(ctx);
        ctx_disable_iv_counter(ctx);

        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);
        return err;
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
