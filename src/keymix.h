#ifndef KEYMIX_H
#define KEYMIX_H

#include "mixctr.h"
#include "types.h"
#include <stdint.h>

// Size of the smallest chunk supported
// It helps with the identification of safe fanout values
#if SIZE_MACRO == 16
#define CHUNK_SIZE 8
#else
#define CHUNK_SIZE 16
#endif

// Pick highest fanouts that are divisor of the block size and satisfy the size
// of the chunk (from bigger to smaller)
int get_available_fanouts(uint8_t n, uint8_t *fanouts);

// The Keymix primitive.
// Applies MixCTR as defined by `mixctrpass` to `in`, putting the result in `out`.
// Here `size` is the size of both input and output, and must be a multiple
// of `SIZE_MACRO`.
// Accepts a positive number of threads, which must be a power of `fanout`.
int keymix(mixctrpass_impl_t mixctrpass, byte *in, byte *out, size_t size, uint8_t fanout,
           uint8_t nof_threads);

#endif
