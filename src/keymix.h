#ifndef KEYMIX_H
#define KEYMIX_H

#include <stdint.h>

#include "mix.h"
#include "types.h"

// Get size of the smallest chunk supported
// It helps with the identification of safe fanout values
int get_chunk_size(block_size_t block_size);

// Pick highest fanouts that are divisor of the block size and satisfy the size
// of the chunk (from bigger to smaller)
int get_fanouts_from_block_size(block_size_t block_size, uint8_t n, uint8_t *fanouts);

// Pick highest fanouts that are divisor of the block size of the given mixing
// primitive type and satisfy the size of the chunk (from bigger to smaller)
int get_fanouts_from_mix_type(mix_t mix_type, uint8_t n, uint8_t *fanouts);

// The Keymix primitive.
// Applies mix as defined by `mixpass` to `in`, putting the result in `out`.
// Here `size` is the size of both input and output, and must be a multiple
// of `block_size`.
// Accepts a positive number of threads, which must be a power of `fanout`.
int keymix(mix_func_t mixpass, byte *in, byte *out, size_t size, block_size_t block_size,
           uint8_t fanout, uint8_t nof_threads);

#endif
