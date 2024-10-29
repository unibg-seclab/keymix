#include "enc.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "keymix.h"
#include "log.h"
#include "types.h"
#include "utils.h"

// ---------------------------------------------- Keymix internals

typedef struct {
        ctx_t *ctx;
        byte *in;
        byte *out;
        size_t resource_size;
        uint64_t keys_to_do;
        byte *iv;
        uint32_t starting_counter;
        uint8_t threads;
} enc_args_t;

void keymix_ctr_mode(enc_args_t *args) {
        ctx_t *ctx = args->ctx;
        byte *src  = (ctx->enc_mode == ENC_MODE_CTR ? ctx->key : ctx->state);

        // The caller is expected to provide an output buffer of the same size
        // of the input, but the keymix always produces a keystream with the
        // size of the key. So, if we are encrypting, we need extra memory to
        // store the result of the keymix
        byte *outbuffer = args->out;
        if (ctx->encrypt) {
                outbuffer = malloc(ctx->key_size);
        }

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;

        for (uint32_t i = 0; i < args->keys_to_do; i++) {
                keymix_iv_counter(ctx, src, outbuffer, ctx->key_size,
                                  args->iv, args->starting_counter + i,
                                  args->threads);
                if (ctx->encrypt) {
                        multi_threaded_memxor(out, outbuffer, in,
                                              MIN(remaining_size, ctx->key_size),
                                              args->threads);
                        in += ctx->key_size;
                }

                out += ctx->key_size;
                if (!ctx->encrypt)
                        outbuffer = out;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        if (ctx->encrypt)
                free(outbuffer);
}

void keymix_ofb_mode(enc_args_t *args) {
        ctx_t *ctx     = args->ctx;
        byte *curr_key = ctx->key;
        byte *next_key = malloc(ctx->key_size);

        // The caller is expected to provide an output buffer of the same size
        // of the input, but the keymix always produces a keystream with the
        // size of the key. So, if we are encrypting, we need extra memory to
        // store the result of the keymix
        byte *outbuffer = args->out;
        if (ctx->encrypt) {
                outbuffer = malloc(ctx->key_size);
        }

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;
        uint64_t nof_macros;
        size_t remaining_one_way_size;

        for (uint64_t i = 0; i < args->keys_to_do; i++) {
                // TODO: Support use of IVs to enable the reuse of the same key
                // for multiple resources. This can only be done on some mixing
                // primitives (i.e., symmetric ciphers and aes derivative
                // hashes)
                keymix(ctx, curr_key, next_key, ctx->key_size, args->threads);
                nof_macros = CEILDIV(remaining_size, ctx->one_way_block_size);
                remaining_one_way_size = ctx->one_way_block_size * nof_macros;
                (*ctx->one_way_mixpass)(next_key, outbuffer,
                                        MIN(remaining_one_way_size, ctx->key_size));
                if (ctx->encrypt) {
                        multi_threaded_memxor(out, outbuffer, in,
                                              MIN(remaining_size, ctx->key_size),
                                              args->threads);
                        in += ctx->key_size;
                }

                curr_key = next_key;
                out += ctx->key_size;
                if (!ctx->encrypt)
                        outbuffer = out;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        free(next_key);
        if (ctx->encrypt)
                free(outbuffer);
}

int keymix_internal(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
                    uint32_t starting_counter, uint8_t threads) {
        if (ctx->enc_mode == ENC_MODE_OFB && starting_counter) {
                _log(LOG_ERROR, "ofb encryption mode does not use counters\n");
                return 1;
        }

        // if (ctx->enc_mode == ENC_MODE_OFB && iv) {
        //         _log(LOG_ERROR, "Reuse of the same key with different IVs for "
        //              "ofb encryption mode is not implemented yet\n");
        //         return 1;
        // }

        enc_args_t arg = {
                .ctx              = ctx,
                .in               = in,
                .out              = out,
                .resource_size    = size,
                .keys_to_do       = CEILDIV(size, ctx->key_size),
                .starting_counter = starting_counter,
                .iv               = iv,
                .threads          = threads,
        };

        if (ctx->enc_mode != ENC_MODE_OFB) {
                keymix_ctr_mode(&arg);
        } else {
                keymix_ofb_mode(&arg);
        }

        return 0;
}

// ---------------------------------------------- Principal interface

int keymix_t(ctx_t *ctx, byte *buffer, size_t size, uint8_t threads) {
        return keymix_ex(ctx, buffer, size, NULL, 0, threads);
}

int keymix_ex(ctx_t *ctx, byte *buffer, size_t size, byte *iv,
              uint32_t starting_counter, uint8_t threads) {
        assert(!ctx->encrypt && "You can't use an encryption context with keymix");
        return keymix_internal(ctx, NULL, buffer, size, iv, starting_counter, threads);
}

int encrypt(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv) {
        return encrypt_ex(ctx, in, out, size, iv, 0, 1);
}

int encrypt_t(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t threads) {
        return encrypt_ex(ctx, in, out, size, iv, 0, threads);
}

int encrypt_ex(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
               uint32_t starting_counter, uint8_t threads) {
        assert(ctx->encrypt && "You must use an encryption context with encrypt");
        return keymix_internal(ctx, in, out, size, iv, starting_counter, threads);
}
