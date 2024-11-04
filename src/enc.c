#include "enc.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "keymix.h"
#include "log.h"
#include "refresh.h"
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
        uint8_t threads;
} enc_args_t;

uint64_t ctr64_get(unsigned char *counter) {
        if (!counter)
                return 0;

        uint64_t c;
        uint64_t ctr64 = 0;
        for (int n = 7; n >= 0; n--) {
                c = counter[n];
                ctr64 |= c << 8 * (7 - n);
        }

        return ctr64;
}

void ctr64_inc(unsigned char *counter) {
        if (!counter)
                return;

        int n = 8;
        unsigned char c;

        do {
                --n;
                c = counter[n];
                ++c;
                counter[n] = c;
                if (c)
                        return;
        } while (n);
}

void keymix_ctr_mode(enc_args_t *args) {
        ctx_t *ctx = args->ctx;
        byte *src;

        // Make a copy of the IV before changing its counter part, to avoid
        // unexpected side effects
        byte *iv      = NULL;
        byte *counter = NULL;
        if (args->iv) {
                iv = malloc(KEYMIX_IV_SIZE);
                memcpy(iv, args->iv, KEYMIX_IV_SIZE);
                counter = iv + KEYMIX_NONCE_SIZE;
        }

        // Extract current uint64_t counter
        uint64_t starting_counter = ctr64_get(counter);

        // Buffer to store the output of the keymix
        byte *outbuffer = malloc(ctx->key_size);

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;

        // Configure the source according to the encryption mode and the
        // refresh parameter
        if (ctx->enc_mode == ENC_MODE_CTR) {
                src = (!ctx->refresh ? ctx->key : outbuffer);
        } else {
                src = ctx->state;
        }

        for (uint32_t i = 0; i < args->keys_to_do; i++) {
                if (ctx->refresh) {
                        multi_threaded_refresh(ctx->key, outbuffer,
                                               ctx->key_size, iv,
                                               (ctx->key_size / BLOCK_SIZE_AES) * (starting_counter + i),
                                               args->threads);
                }
                keymix_ex(ctx, src, outbuffer, ctx->key_size, iv,
                          args->threads);
                multi_threaded_memxor(out, outbuffer, in,
                                      MIN(remaining_size, ctx->key_size),
                                      args->threads);
                ctr64_inc(counter);

                in += ctx->key_size;
                out += ctx->key_size;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        if (args->iv) {
                explicit_bzero(iv, KEYMIX_IV_SIZE);
                free(iv);
        }
        free(outbuffer);
}

// To enable the use of the ofb encryption mode with streams, this function
// works as an iterator keeping track of the next key to use in its internal
// state. Unfortunately, this means we cannot reuse the same context as is for
// multiple encryptions/decryptions. However, it is always possible to reset
// the context to its initial form by resetting the state to the initial key
void keymix_ofb_mode(enc_args_t *args) {
        ctx_t *ctx     = args->ctx;

        // Buffer to store the output of the keymix
        byte *outbuffer = malloc(ctx->key_size);

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;
        uint64_t nof_macros;
        size_t remaining_one_way_size;

        for (uint64_t i = 0; i < args->keys_to_do; i++) {
                keymix_ex(ctx, ctx->state, ctx->state, ctx->key_size, args->iv,
                          args->threads);
                nof_macros = CEILDIV(remaining_size, ctx->one_way_block_size);
                remaining_one_way_size = ctx->one_way_block_size * nof_macros;
                multi_threaded_mixpass(ctx->one_way_mixpass,
                                       ctx->one_way_block_size,
                                       ctx->state, outbuffer,
                                       MIN(remaining_one_way_size, ctx->key_size),
                                       args->iv, args->threads);
                multi_threaded_memxor(out, outbuffer, in,
                                      MIN(remaining_size, ctx->key_size),
                                      args->threads);

                in += ctx->key_size;
                out += ctx->key_size;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        free(outbuffer);
}

int keymix_encrypt(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
                    uint8_t threads) {
        // mix_info_t mix_info = *get_mix_info(ctx->mix);
        // if (ctx->enc_mode == ENC_MODE_OFB && mix_info.is_one_way && iv) {
        //         _log(LOG_ERROR, "ofb encryption mode does not support IVs for "
        //              "one-way mixing primitives yet\n");
        //         return 1;
        // }

        enc_args_t arg = {
                .ctx              = ctx,
                .in               = in,
                .out              = out,
                .resource_size    = size,
                .keys_to_do       = CEILDIV(size, ctx->key_size),
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

int encrypt(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv) {
        return encrypt_t(ctx, in, out, size, iv, 1);
}

int encrypt_t(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t threads) {
        assert(ctx->encrypt && "You must use an encryption context with encrypt");
        return keymix_encrypt(ctx, in, out, size, iv, threads);
}
