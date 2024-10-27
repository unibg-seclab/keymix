#ifndef ENC_H
#define ENC_H

#include "ctx.h"
#include <stdint.h>

// Callable functions

// Same as `keymix_ex` but with `starting_counter` set to 0
int keymix_t(ctx_t *ctx, byte *buffer, size_t size, uint8_t threads);

// Threaded keymix applied in-place to `buffer`.
int keymix_ex(ctx_t *ctx, byte *out, size_t size, uint8_t threads,
              uint32_t starting_counter);

// Same as `encrypt_ex` but with `starting_counter` set to 0 and no threads
int encrypt(ctx_t *ctx, byte *in, byte *out, size_t size);

// Same as `encrypt_ex` but with `starting_counter` set to 0
int encrypt_t(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t threads);

// Threaded encryption applied to `in` and outputting the result to `out`.
// The two can be the same pointer if the operation is to be done in-place.
int encrypt_ex(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t threads,
               uint32_t starting_counter);

#endif
