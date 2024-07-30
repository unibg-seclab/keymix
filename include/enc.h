#ifndef ENC_H
#define ENC_H

#include "mixctr.h"
#include "types.h"

// The context for keymix operations. It houses all shared information that
// won't be modified by the algorithm.
typedef struct {
        // The secret key.
        byte *key;

        // The key's size, its number of 48-B blocks must be a power of fanout.
        size_t key_size;

        // The AES implementation to consider.
        mixctr_t mixctr;

        // The MixCTR implementation.
        mixctrpass_impl_t mixctrpass;

        // The fanout for the shuffle/spread part, can only be 2, 3, or 4
        fanout_t fanout;

        // The initial IV to XOR with the first block of the key.
        // This is only done if `do_iv_counter` is enabled.
        uint128_t iv;

        // Marks this context as an encryption context.
        // That is, to do the XOR after the keymix.
        bool encrypt;

        // If `true`, indicates keymix to apply the IV to the first block
        // and increasing counters to the following ones.
        // Otherwise, this step is skipped.
        bool do_iv_counter;
} keymix_ctx_t;

// Context initialization

// Initializes the context `ctx` for encryption purposes with a certain `key` and setting an `iv`.
void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                      fanout_t fanout);

// Initializes the context `ctx` for keymix-only purposes with a certain `key`.
void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout);

// Updates the context `ctx` to enable the XOR operation after doing the keymix.
inline void ctx_enable_encryption(keymix_ctx_t *ctx) { ctx->encrypt = true; }

// Updates the context `ctx` to disable the XOR operation after doing the keymix.
inline void ctx_disable_encryption(keymix_ctx_t *ctx) { ctx->encrypt = false; }

// Updates the context `ctx` to enable the application of IV and counter to the key.
// Must provide an IV.
inline void ctx_enable_iv_counter(keymix_ctx_t *ctx, uint128_t iv) {
        ctx->do_iv_counter = true;
        ctx->iv            = iv;
}
// Updates the context `ctx` to disable the application of IV and counter to the key.
inline void ctx_disable_iv_counter(keymix_ctx_t *ctx) {
        ctx->do_iv_counter = false;
        ctx->iv            = 0;
}

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
