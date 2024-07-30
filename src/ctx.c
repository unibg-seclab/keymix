#include "ctx.h"

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                      fanout_t fanout) {
        ctx->key        = key;
        ctx->key_size   = size;
        ctx->mixctr     = mixctr;
        ctx->mixctrpass = get_mixctr_impl(mixctr);
        ctx->fanout     = fanout;
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);
}

void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout) {
        ctx->key        = key;
        ctx->key_size   = size;
        ctx->mixctr     = mixctr;
        ctx->mixctrpass = get_mixctr_impl(mixctr);
        ctx->fanout     = fanout;
        ctx_disable_encryption(ctx);
        ctx_disable_iv_counter(ctx);
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
