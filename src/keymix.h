#ifndef KEYMIX_H
#define KEYMIX_H

#include <stdint.h>

#include "ctx.h"
#include "mix.h"
#include "types.h"

#define MIXPASS_DEFAULT_IV "super_mix_iv"

// Pick highest fanouts that are divisor of the block size and satisfy the size
// of the chunk (from bigger to smaller)
int get_fanouts_from_block_size(block_size_t block_size, uint8_t n, uint8_t *fanouts);

// Pick highest fanouts that are divisor of the block size of the given mixing
// primitive type and satisfy the size of the chunk (from bigger to smaller)
int get_fanouts_from_mix_type(mix_impl_t mix_type, uint8_t n, uint8_t *fanouts);

// Get number of encryption levels in the keymix computation
uint8_t get_levels(size_t size, block_size_t block_size, uint8_t fanout);

// Same as `keymix_iv_counter` but with IV set to NULL and counter set to 0
int keymix(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t nof_threads);

// Same as `keymix_iv` but with counter set to 0
int keymix_iv(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t nof_threads);

// The Keymix primitive.
// Applies mix as defined by `ctx->mixpass` to `in`, putting the result in
// `out`. Here `size` is the size of both input and output, and must be a
// multiple of the `block_size` by a power of `fanout`.
// 96-bit IV and 32-bit counter are applied on the 1st 128 bits of `in` to
// generate a fresh keysteam.
int keymix_iv_counter(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
                      uint32_t counter, uint8_t nof_threads);

#endif
