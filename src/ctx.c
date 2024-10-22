#include "ctx.h"

#include <string.h>
#include <openssl/evp.h>

#include "utils.h"

int ctx_keymix_init(ctx_t *ctx, mix_t mix, byte *key, size_t size, uint8_t fanout) {
        if (get_mix_func(mix, &ctx->mixpass, &ctx->block_size)) {
                return CTX_ERR_NOMIXCTR;
        }

        size_t num_macros = size / ctx->block_size;
        if (size % ctx->block_size != 0 || !ISPOWEROF(num_macros, fanout)) {
                return CTX_ERR_KEYSIZE;
        }

        ctx->enc_mode = CTR;
        ctx->key      = key;
        ctx->key_size = size;
        ctx->mix      = mix;
        ctx->fanout   = fanout;
        ctx_disable_encryption(ctx);
        ctx_disable_iv_counter(ctx);

        return 0;
}

int ctx_encrypt_init(ctx_t *ctx, enc_mode_t enc_mode, mix_t mix, mix_t one_way_mix, byte *key,
                     size_t size, uint128_t iv, uint8_t fanout) {
        int err = ctx_keymix_init(ctx, mix, key, size, fanout);
        if (err) {
                return err;
        }

        if (get_mix_func(one_way_mix, &ctx->one_way_mixpass, &ctx->one_way_block_size)) {
                return CTX_ERR_NOMIXCTR;
        }

        ctx->enc_mode    = enc_mode;
        ctx->one_way_mix = one_way_mix;
        ctx_enable_encryption(ctx);
        ctx_enable_iv_counter(ctx, iv);

        return 0;
}

inline void ctx_enable_encryption(ctx_t *ctx) { ctx->encrypt = true; }

inline void ctx_disable_encryption(ctx_t *ctx) { ctx->encrypt = false; }

inline void ctx_enable_iv_counter(ctx_t *ctx, uint128_t iv) {
        ctx->do_iv_counter = true;
        ctx->iv            = iv;
}
inline void ctx_disable_iv_counter(ctx_t *ctx) {
        ctx->do_iv_counter = false;
        ctx->iv            = 0;
}

char *ENC_NAMES[] = { "ctr", "ofb" };

char *get_enc_mode_name(enc_mode_t enc_mode) {
        return ENC_NAMES[enc_mode];
}

enc_mode_t get_enc_mode_type(char* name) {
        for (int8_t i = 0; i < sizeof(ENC_NAMES) / sizeof(*ENC_NAMES); i++)
        if (strcmp(name, ENC_NAMES[i]) == 0)
                return (enc_mode_t)i;
        return -1;
}
