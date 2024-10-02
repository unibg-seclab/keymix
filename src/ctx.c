#include "ctx.h"
#include "utils.h"
#include <assert.h>

#include <openssl/evp.h>

void ctx_init(keymix_ctx_t *ctx, mix_t mix, byte *key, size_t size, uint8_t fanout) {
        size_t num_macros = size / BLOCK_SIZE;
        assert(size % BLOCK_SIZE == 0 && ISPOWEROF(num_macros, fanout) &&
               "Number of blocks in the key MUST be a power of the fanout");
        ctx->key      = key;
        ctx->key_size = size;
        ctx->mix      = mix;
        ctx->mixpass  = get_mix_impl(mix);
        ctx->fanout   = fanout;
}

void ctx_encrypt_init(keymix_ctx_t *ctx, mix_t mixctr, byte *key, size_t size, uint128_t iv,
                      uint8_t fanout) {
        ctx_init(ctx, mixctr, key, size, fanout);
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);
}

void ctx_keymix_init(keymix_ctx_t *ctx, mix_t mixctr, byte *key, size_t size, uint8_t fanout) {
        ctx_init(ctx, mixctr, key, size, fanout);
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
