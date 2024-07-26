#include "enc.h"

#include "aesni.h"
#include "assert.h"
#include "keymix.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------- Context init

inline mixctrpass_impl_t get_impl(mixctrpass_t name) {
        switch (name) {
        case MIXCTRPASS_WOLFSSL:
                return &wolfssl;
        case MIXCTRPASS_OPENSSL:
                return &openssl;
        case MIXCTRPASS_AESNI:
                return &aesni;
        }
}

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *key, size_t size,
                      uint128_t iv, fanout_t fanout) {
        ctx_keymix_init(ctx, mixctrpass, key, size, fanout);
        ctx->iv      = iv;
        ctx->encrypt = true;
}

void ctx_keymix_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, size_t size,
                     fanout_t diffusion) {
        ctx->key      = secret;
        ctx->key_size = size;

        ctx->mixctrpass = get_impl(mixctrpass);
        ctx->fanout     = diffusion;
        ctx->encrypt    = false;
}

// ---------------------------------------------- Code implementation

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

void *w_keymix(void *a) {
        worker_args_t *args = (worker_args_t *)a;
        keymix_ctx_t *ctx   = args->ctx;

        // Keep a local copy of the seed: it needs to be modified, and we are
        // in a multithreaded environment, so we can't just overwrite the same
        // memory area while other threads are trying to read it and modify it
        // themselves
        byte *buffer = malloc(ctx->key_size);
        memcpy(buffer, ctx->key, ctx->key_size);

        // The seed gets modified as follows
        // First block -> XOR with (unchanging) IV
        // Second block -> incremented

        uint128_t *buffer_as_blocks = (uint128_t *)buffer;
        if (ctx->encrypt) {
                buffer_as_blocks[0] ^= ctx->iv;
                buffer_as_blocks[1] += args->counter;
        }

        byte *in              = args->in;
        byte *out             = args->out;
        size_t remaining_size = args->resource_size;

        for (uint64_t i = 0; i < args->keys_to_do; i++) {
                mixing_config conf = {ctx->mixctrpass, ctx->fanout};
                keymix(buffer, out, ctx->key_size, &conf, args->internal_threads);

                if (ctx->encrypt) {
                        memxor(out, in, MIN(remaining_size, ctx->key_size));
                        in += ctx->key_size;
                        buffer_as_blocks[1]++;
                }

                out += ctx->key_size;
                if (remaining_size >= ctx->key_size)
                        remaining_size -= ctx->key_size;
        }

        free(buffer);
        return NULL;
}

// int keymix_ex(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config
// *config,
//               uint8_t num_threads, uint8_t internal_threads, uint128_t iv,
//               uint128_t starting_counter) {
int keymix_ex(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
              uint8_t internal_threads, uint128_t starting_counter) {
        pthread_t threads[external_threads];
        worker_args_t args[external_threads];

        uint64_t keys_to_do   = ceil((double)size / ctx->key_size);
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
                        remaining_size -= ctx->key_size;
                counter += thread_keys;
        }

        assert(keys_to_do == 0);

        for (uint8_t t = 0; t < started_threads; t++) {
                pthread_join(threads[t], NULL);
        }

        return 0;
}
int keymix_t(keymix_ctx_t *ctx, byte *out, size_t size, uint8_t external_threads,
             uint8_t internal_threads) {
        return keymix_ex(ctx, NULL, out, size, external_threads, internal_threads, 0);
}
