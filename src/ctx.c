#include "ctx.h"

#include <string.h>
#include <openssl/evp.h>

#include "keymix.h"
#include "spread.h"
#include "utils.h"

ctx_err_t ctx_keymix_init(ctx_t *ctx, mix_impl_t mix, byte *key, size_t size, uint8_t fanout) {
        ctx->state = NULL;

        if (get_mix_func(mix, &ctx->mixpass, &ctx->block_size)) {
                return CTX_ERR_UNKNOWN_MIX;
        }

        if (mix == NONE) {
                return CTX_ERR_MISSING_MIX;
        }

        size_t num_macros = size / ctx->block_size;
        if (size % ctx->block_size != 0 || !ISPOWEROF(num_macros, fanout)) {
                return CTX_ERR_KEYSIZE;
        }

        ctx->enc_mode = ENC_MODE_CTR;
        ctx->key      = key;
        ctx->key_size = size;
        ctx->mix      = mix;
        ctx->fanout   = fanout;
        ctx_disable_encryption(ctx);

        return CTX_ERR_NONE;
}

ctx_err_t ctx_encrypt_init(ctx_t *ctx, enc_mode_t enc_mode, mix_impl_t mix, mix_impl_t one_way_mix,
                           byte *key, size_t size, uint8_t fanout) {
        ctx->state = NULL;

        int err = ctx_keymix_init(ctx, mix, key, size, fanout);
        if (err) {
                return err;
        }

        if (get_mix_func(one_way_mix, &ctx->one_way_mixpass, &ctx->one_way_block_size)) {
                return CTX_ERR_UNKNOWN_ONE_WAY_MIX;
        }

        mix_info_t mix_info = *get_mix_info(mix);
        mix_info_t one_way_mix_info = *get_mix_info(one_way_mix);

        // Ensure the one-way mixing primitive is indeed a one-way primitive
        if (!one_way_mix_info.is_one_way) {
                return CTX_ERR_NOT_ONE_WAY;
        }

        // Ensure the one-way mixing implementation is specified with the OFB
        // encryption mode
        if (enc_mode == ENC_MODE_OFB && one_way_mix == NONE) {
                return CTX_ERR_MISSING_ONE_WAY_MIX;
        }

        // Ensure compatibility between mixing and one-way primitive
        block_size_t big   = MAX(ctx->block_size, ctx->one_way_block_size);
        block_size_t small = MIN(ctx->block_size, ctx->one_way_block_size);
        if (small && big % small) {
                return CTX_ERR_INCOMPATIBLE_PRIMITIVES;
        }

        // Ensure the mixing primitive are not the same with the OFB encryption mode.
        // Indeed, this would compromise the security of the encryption
        if (enc_mode == ENC_MODE_OFB && mix_info.primitive == one_way_mix_info.primitive) {
                return CTX_ERR_EQUAL_PRIMITIVES;
        }

        // Ensure the block size of the one-way mixing primitive is a divisor
        // of the key size
        if (one_way_mix != NONE && size % ctx->one_way_block_size) {
                return CTX_ERR_KEYSIZE;
        }

        ctx->enc_mode    = enc_mode;
        ctx->one_way_mix = one_way_mix;
        ctx_enable_encryption(ctx);

        if (enc_mode == ENC_MODE_CTR_OPT) {
                ctx_precompute_state(ctx);
        }

        return CTX_ERR_NONE;
}

inline void ctx_enable_encryption(ctx_t *ctx) { ctx->encrypt = true; }

inline void ctx_disable_encryption(ctx_t *ctx) { ctx->encrypt = false; }

void ctx_precompute_state(ctx_t *ctx) {
        byte *curr;
        size_t prev_size;
        size_t curr_size;
        uint8_t levels;

        ctx->state = malloc(ctx->key_size);
        curr       = ctx->state;
        prev_size  = 1;
        curr_size  = ctx->block_size;
        levels = get_levels(ctx->key_size, ctx->block_size, ctx->fanout);

        // Copy key changed with iv and counter
        memcpy(curr, ctx->key, ctx->block_size);
        curr += ctx->block_size;

        // Keymix to compute only the internal state that is kept equal across
        // all iv and counter values

        spread_args_t args = {
                .thread_id       = 0,
                .nof_threads     = 1,
                .fanout          = ctx->fanout,
                .block_size      = ctx->block_size,
        };

        (*ctx->mixpass)(ctx->key + ctx->block_size, curr, ctx->key_size - curr_size);

        for (args.level = 1; args.level < levels; args.level++) {
                // Keep internal state not yet affected by iv and counter that
                // will be affected at the current layer
                prev_size = curr_size;
                curr_size = ctx->fanout * prev_size;
                curr += curr_size - prev_size;

                args.buffer          = curr;
                args.buffer_abs      = curr;
                args.buffer_abs_size = ctx->key_size - curr_size,
                args.buffer_size     = ctx->key_size - curr_size,

                spread(&args);
                (*ctx->mixpass)(curr, curr, ctx->key_size - curr_size);
        }
}

inline void ctx_free(ctx_t *ctx) {
        if (ctx->enc_mode == ENC_MODE_CTR_OPT && ctx->state != NULL) {
                explicit_bzero(ctx->state, ctx->key_size);
                free(ctx->state);
        }
}

char *ENC_NAMES[] = { "ctr", "ctr-opt", "ofb" };

char *get_enc_mode_name(enc_mode_t enc_mode) {
        uint8_t n = sizeof(ENC_NAMES) / sizeof(*ENC_NAMES);
        if (enc_mode < 0 || enc_mode >= n) {
                return NULL;
        }

        return ENC_NAMES[enc_mode];
}

enc_mode_t get_enc_mode_type(char* name) {
        for (int8_t i = 0; i < sizeof(ENC_NAMES) / sizeof(*ENC_NAMES); i++)
                if (strcmp(name, ENC_NAMES[i]) == 0)
                        return (enc_mode_t)i;
        return -1;
}
