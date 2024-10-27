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
        uint32_t counter;
        uint8_t threads;
} enc_args_t;

inline void _reverse32bits(uint32_t *x) {
        byte *data  = (byte *)x;
        size_t size = sizeof(*x);
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define __correct_endianness(...) _reverse32bits(__VA_ARGS_)
#else
#define __correct_endianness(...)
#endif

void keymix_ctr_mode(enc_args_t *args) {
        ctx_t *ctx = args->ctx;

        // Keep the key unchanged across multiple calls
        // TODO: Overall copying the entire key to just change its first block
        // is super overkill so find a way to avoid this
        byte *tmpkey = malloc(ctx->key_size);
        byte *src    = (ctx->enc_mode == ENC_MODE_CTR ? ctx->key : ctx->state);
        memcpy(tmpkey, src, ctx->key_size);

        // The caller is expected to provide an output buffer of the same size
        // of the input, but the keymix always produces a keystream with the
        // size of the key. So, if we are encrypting, we need extra memory to
        // store the result of the keymix
        byte *outbuffer = args->out;
        if (ctx->encrypt) {
                outbuffer = malloc(ctx->key_size);
        }

        // The key gets modified as follows
        // XOR IV with 1st 96 bits of the key
        // Sum counter to the following 32 bits of the key
        uint32_t *counter = (uint32_t*)(tmpkey + KEYMIX_IV_SIZE);
        if (ctx->do_iv_counter) {
                memxor(tmpkey, tmpkey, ctx->iv, KEYMIX_IV_SIZE);

                __correct_endianness(counter);
                *counter += args->counter;
                __correct_endianness(counter);
        }

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;

        for (uint64_t i = 0; i < args->keys_to_do; i++) {
                keymix(ctx, tmpkey, outbuffer, ctx->key_size, args->threads);
                if (ctx->encrypt) {
                        memxor(out, outbuffer, in, MIN(remaining_size, ctx->key_size));
                        in += ctx->key_size;
                }
                if (ctx->do_iv_counter) {
                        __correct_endianness(&key_as_blocks[1]);
                        (*counter)++;
                        __correct_endianness(&key_as_blocks[1]);
                }

                out += ctx->key_size;
                if (!ctx->encrypt)
                        outbuffer = out;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        free(tmpkey);
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
                keymix(ctx, curr_key, next_key, ctx->key_size, args->threads);
                nof_macros = CEILDIV(remaining_size, ctx->one_way_block_size);
                remaining_one_way_size = ctx->one_way_block_size * nof_macros;
                (*ctx->one_way_mixpass)(next_key, outbuffer,
                                        MIN(remaining_one_way_size, ctx->key_size));
                if (ctx->encrypt) {
                        memxor(out, outbuffer, in, MIN(remaining_size, ctx->key_size));
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

int keymix_internal(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t threads,
                    uint32_t starting_counter) {
        if (ctx->enc_mode == ENC_MODE_CTR_OPT && threads != 1) {
                _log(LOG_ERROR, "Internal parallelization of the optimized "
                     "ctr encryption is not implemented yet");
                return 1;
        }

        enc_args_t arg = {
                .ctx           = ctx,
                .in            = in,
                .out           = out,
                .resource_size = size,
                .keys_to_do    = CEILDIV(size, ctx->key_size),
                .counter       = starting_counter,
                .threads       = threads,
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
        return keymix_ex(ctx, buffer, size, threads, 0);
}

int keymix_ex(ctx_t *ctx, byte *buffer, size_t size, uint8_t threads,
              uint32_t starting_counter) {
        assert(!ctx->encrypt && "You can't use an encryption context with keymix");
        return keymix_internal(ctx, NULL, buffer, size, threads, starting_counter);
}

int encrypt(ctx_t *ctx, byte *in, byte *out, size_t size) {
        return encrypt_ex(ctx, in, out, size, 1, 0);
}

int encrypt_t(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t threads) {
        return encrypt_ex(ctx, in, out, size, threads, 0);
}

int encrypt_ex(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t threads,
               uint32_t starting_counter) {
        assert(ctx->encrypt && ctx->do_iv_counter &&
               "You must use an encryption context with encrypt");
        return keymix_internal(ctx, in, out, size, threads, starting_counter);
}
