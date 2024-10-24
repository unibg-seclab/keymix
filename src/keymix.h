#ifndef KEYMIX_H
#define KEYMIX_H

#include <stdint.h>

#include "mix.h"
#include "types.h"

// Pick highest fanouts that are divisor of the block size and satisfy the size
// of the chunk (from bigger to smaller)
int get_fanouts_from_block_size(block_size_t block_size, uint8_t n, uint8_t *fanouts);

// Pick highest fanouts that are divisor of the block size of the given mixing
// primitive type and satisfy the size of the chunk (from bigger to smaller)
int get_fanouts_from_mix_type(mix_impl_t mix_type, uint8_t n, uint8_t *fanouts);

// The Keymix primitive.
// Applies mix as defined by `mixpass` to `in`, putting the result in `out`.
// Here `size` is the size of both input and output, and must be a multiple
// of `block_size`.
// Accepts a positive number of threads, which must be a power of `fanout`.
int keymix(mix_impl_t mix_type, byte *in, byte *out, size_t size, uint8_t fanout,
           uint8_t nof_threads);

#endif
