#ifndef KEYMIX_H
#define KEYMIX_H

#include <stdint.h>

#include "ctx.h"
#include "mix.h"
#include "types.h"

#define MIXPASS_DEFAULT_IV "_super_secure_iv"

// Pick highest fanouts that are divisor of the block size and satisfy the size
// of the chunk (from bigger to smaller)
int get_fanouts_from_block_size(block_size_t block_size, uint8_t n, uint8_t *fanouts);

// Pick highest fanouts that are divisor of the block size of the given mixing
// primitive type and satisfy the size of the chunk (from bigger to smaller)
int get_fanouts_from_mix_type(mix_impl_t mix_type, uint8_t n, uint8_t *fanouts);

// Get number of encryption levels in the keymix computation
uint8_t get_levels(size_t size, block_size_t block_size, uint8_t fanout);

// Same as `keymix_ex` but without IV and with a single thread.
int keymix(ctx_t *ctx, byte *out, size_t size);

// Same as `keymix_ex` but without the IV.
int keymix_t(ctx_t *ctx, byte *out, size_t size, uint8_t threads);

// The Keymix primitive.
// Applies mix as defined by `ctx->mixpass` to `in`, putting the result in
// `out`. Here `size` is the size of both input and output, and must be a
// multiple of the `block_size` by a power of `fanout`.
// An IV of 64-bit nonce and 64-bit counter is applied on the 1st 128 bits
// of `in` to generate a fresh keysteam
int keymix_ex(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t nof_threads);

#endif
