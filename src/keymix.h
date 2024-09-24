#ifndef KEYMIX_H
#define KEYMIX_H

#include "ctx.h"
#include "mixctr.h"
#include "types.h"
#include <stdint.h>

// The Keymix primitive.
// Applies MixCTR as defined by `mixctr` to `in`, putting the result in `out`.
// Here `size` is the size of both input and output, and must be a multiple
// of the input size to the MixCTR.
// Accepts a positive number of threads, which must be a power of `fanout`.
int keymix(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t nof_threads);

#endif
