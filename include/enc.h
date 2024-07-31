#ifndef ENC_H
#define ENC_H

#include "ctx.h"
#include <stdint.h>

// Callable functions

// Same as `keymix_ex` but with `starting_counter` set to 0
int keymix_t(keymix_ctx_t *ctx, byte *buffer, size_t size, uint8_t external_threads,
             uint8_t internal_threads);

// Threaded keymix applied in-place to `buffer`.
// - `external_threads` indicates how many threads to use for the various
//   epochs to do, based on the ratio between `size` and `ctx->key_size`.
// - `size` must be a multiple of `ctx->key_size`
// - `internal_threads` indicates how many threads to use internally for
//   the keymix function. Must be a power of `ctx->fanout`.
int keymix_ex(keymix_ctx_t *ctx, byte *out, size_t size, uint8_t external_threads,
              uint8_t internal_threads, uint128_t starting_counter);

// Same as `encrypt_ex` but with `starting_counter` set to 0 and no threads
int encrypt(keymix_ctx_t *ctx, byte *in, byte *out, size_t size);

// Same as `encrypt_ex` but with `starting_counter` set to 0
int encrypt_t(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
              uint8_t internal_threads);

// Threaded encryption applied to `in` and outputting the result to `out`.
// The two can be the same pointer if the operation is to be done in-place.
// - `external_threads` indicates how many threads to use for the various
//   epochs to do, based on the ratio between `out_size` and `ctx->key_size`.
// - `internal_threads` indicates how many threads to use internally for
//   the keymix function. Must be a power of `ctx->fanout`.
int encrypt_ex(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
               uint8_t internal_threads, uint128_t starting_counter);

#endif
