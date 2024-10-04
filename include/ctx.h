#ifndef CTX_H
#define CTX_H

#include "mixctr.h"
#include "types.h"
#include <stdbool.h>

typedef enum {
        CTX_ERR_NOMIXCTR = 1,
        CTX_ERR_KEYSIZE  = 2,
} ctx_err_t;

// The context for keymix operations. It houses all shared information that
// won't be modified by the algorithm.
typedef struct {
        // The secret key.
        byte *key;

        // The key's size, its number of 48-B blocks must be a power of fanout.
        size_t key_size;

        // The MixCTR implementation...
        mixctr_impl_t mixctr_impl;
        // ... and its name
        mixctr_t mixctr_name;

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

        // The size of the input to the MixCTR.
        // Useful when using different techniques, for now it is always 48 B.
        size_t size_macro;
} keymix_ctx_t;

// Context initialization

// Initializes the context `ctx` for encryption purposes with a certain `key` and setting an `iv`.
int ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, uint128_t iv,
                     fanout_t fanout);

// Initializes the context `ctx` for keymix-only purposes with a certain `key`.
int ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *key, size_t size, fanout_t fanout);

// Updates the context `ctx` to enable the XOR operation after doing the keymix.
void ctx_enable_encryption(keymix_ctx_t *ctx);

// Updates the context `ctx` to disable the XOR operation after doing the keymix.
void ctx_disable_encryption(keymix_ctx_t *ctx);

// Updates the context `ctx` to enable the application of IV and counter to the key.
// Must provide an IV.
void ctx_enable_iv_counter(keymix_ctx_t *ctx, uint128_t iv);

// Updates the context `ctx` to disable the application of IV and counter to the key.
void ctx_disable_iv_counter(keymix_ctx_t *ctx);

#endif
