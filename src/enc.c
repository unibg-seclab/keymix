#include "enc.h"

#include "assert.h"
#include "keymix.h"
#include "types.h"
#include "utils.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------- Keymix internals

typedef struct {
        keymix_ctx_t *ctx;
        // byte *key;
        // size_t key_size;
        uint64_t keys_to_do;

        byte *in;
        size_t resource_size;

        byte *out;

        // uint128_t iv;
        uint128_t counter;

        // mixctrpass_impl_t mixctrpass;
        // fanout_t fanout;
        uint8_t internal_threads;
} worker_args_t;

// Note: this two functions are currently unused, because we increment directly
// using a cast to uint128_t. If we want to not have endianness stuff, we can
// just switch to these.
inline void _reverse128bits(uint128_t *x) {
        byte *data  = (byte *)x;
        size_t size = SIZE_BLOCK;
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define __correct_endianness(...) _reverse128bits(__VA_ARGS_)
#else
#define __correct_endianness(...)
#endif

void *w_keymix(void *a) {
        worker_args_t *args = (worker_args_t *)a;
        keymix_ctx_t *ctx   = args->ctx;

        // Keep a local copy of the key: it needs to be modified, and we are
        // in a multithreaded environment, so we can't just overwrite the same
        // memory area while other threads are trying to read it and modify it
        // themselves
        byte *tmpkey = malloc(ctx->key_size);
        memcpy(tmpkey, ctx->key, ctx->key_size);

        // If we are encrypting, then we have to consider one thing: the
        // keymix always spits out a key_size, so what happens if we have
        // a resource (or a piece of a resource) to encrypt that is smaller than the key?
        // We write out of bounds. So, if we are encrypting, we have to save
        // the result of keymix somewhere, and then do the xor only on the
        // corresponding part.
        byte *outbuffer = args->out;
        if (ctx->encrypt) {
                outbuffer = malloc(ctx->key_size);
        }

        // The key gets modified as follows
        // First block -> XOR with (unchanging) IV
        // Second block -> incremented

        uint128_t *key_as_blocks = (uint128_t *)tmpkey;

        if (ctx->do_iv_counter) {
                __correct_endianness(&key_as_blocks[0]);
                __correct_endianness(&key_as_blocks[1]);

                key_as_blocks[0] ^= ctx->iv;
                key_as_blocks[1] += args->counter;

                __correct_endianness(&key_as_blocks[0]);
                __correct_endianness(&key_as_blocks[1]);
        }

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;

        for (uint64_t i = 0; i < args->keys_to_do; i++) {
                keymix(ctx->mixctrpass, tmpkey, outbuffer, ctx->key_size, ctx->fanout,
                       args->internal_threads);

                if (ctx->encrypt) {
                        memxor(out, outbuffer, in, MIN(remaining_size, ctx->key_size));
                        in += ctx->key_size;
                }
                if (ctx->do_iv_counter) {
                        __correct_endianness(&key_as_blocks[1]);
                        key_as_blocks[1]++;
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
        return NULL;
}

int keymix_internal(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
                    uint8_t internal_threads, uint128_t starting_counter) {
        pthread_t threads[external_threads];
        worker_args_t args[external_threads];

        uint64_t keys_to_do   = CEILDIV(size, ctx->key_size);
        uint128_t counter     = starting_counter;
        size_t remaining_size = size;

        uint64_t offset         = 0;
        uint8_t started_threads = 0;

        for (uint8_t t = 0; t < external_threads; t++) {
                if (keys_to_do == 0) {
                        break;
                }

                uint64_t thread_keys = MAX(1UL, keys_to_do / (external_threads - t));
                uint64_t thread_size = thread_keys * ctx->key_size;
                keys_to_do -= thread_keys;

                worker_args_t *a    = &args[t];
                a->ctx              = ctx;
                a->keys_to_do       = thread_keys;
                a->in               = in;
                a->resource_size    = MIN(thread_size, remaining_size);
                a->out              = out;
                a->counter          = counter;
                a->internal_threads = internal_threads;

                pthread_create(threads + t, NULL, w_keymix, a);
                started_threads++;

                out += thread_size;
                if (ctx->encrypt)
                        in += thread_size;
                if (remaining_size > ctx->key_size)
                        remaining_size -= thread_size;
                counter += thread_keys;
        }

        assert(keys_to_do == 0);

        for (uint8_t t = 0; t < started_threads; t++) {
                pthread_join(threads[t], NULL);
        }

        return 0;
}

// ---------------------------------------------- Principal interface

int keymix_t(keymix_ctx_t *ctx, byte *buffer, size_t size, uint8_t external_threads,
             uint8_t internal_threads) {
        return keymix_ex(ctx, buffer, size, external_threads, internal_threads, 0);
}

int keymix_ex(keymix_ctx_t *ctx, byte *buffer, size_t size, uint8_t external_threads,
              uint8_t internal_threads, uint128_t starting_counter) {
        assert(!ctx->encrypt && "You can't use an encryption context with keymix");
        return keymix_internal(ctx, NULL, buffer, size, external_threads, internal_threads,
                               starting_counter);
}

int encrypt(keymix_ctx_t *ctx, byte *in, byte *out, size_t size) {
        return encrypt_ex(ctx, in, out, size, 1, 1, 0);
}

int encrypt_t(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
              uint8_t internal_threads) {
        return encrypt_ex(ctx, in, out, size, external_threads, internal_threads, 0);
}

int encrypt_ex(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
               uint8_t internal_threads, uint128_t starting_counter) {
        assert(ctx->encrypt && ctx->do_iv_counter &&
               "You must use an encryption context with encrypt");
        return keymix_internal(ctx, in, out, size, external_threads, internal_threads,
                               starting_counter);
}
