#ifndef ENC_H
#define ENC_H

#include <stdint.h>

#include "ctx.h"

// Callable functions

// Get counter in 64-bit unsigned int format
uint64_t ctr64_get(unsigned char *counter);

// Increment counter (64-bit int) by 1
// (from https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes.c)
void ctr64_inc(unsigned char *counter);

// Same as `encrypt_t` but with no threads.
int encrypt(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv);

// Threaded encryption applied to `in` and outputting the result to `out`.
// The two can be the same pointer if the operation is to be done in-place.
int encrypt_t(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t threads);

#endif
