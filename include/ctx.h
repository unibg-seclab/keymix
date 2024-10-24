#ifndef CTX_H
#define CTX_H

#include <stdbool.h>
#include <stdint.h>

#include "mix.h"
#include "types.h"

typedef enum {
        ENC_MODE_CTR,
        ENC_MODE_OFB,
} enc_mode_t;

typedef enum {
        CTX_ERR_NONE,
        CTX_ERR_UNKNOWN_MIX,
        CTX_ERR_MISSING_MIX,
        CTX_ERR_UNKNOWN_ONE_WAY_MIX,
        CTX_ERR_MISSING_ONE_WAY_MIX,
        CTX_ERR_KEYSIZE,
} ctx_err_t;

// The context for keymix operations. It houses all shared information that
// won't be modified by the algorithm.
typedef struct {
        // The secret key.
        byte *key;

        // The key's size, its number of blocks must be a power of fanout.
        size_t key_size;

        // The mix type to consider.
        mix_t mix;

        // The mix implementation.
        mix_func_t mixpass;

        // The fanout for the shuffle/spread part, can only be 2, 3, or 4
        uint8_t fanout;

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

        // Input/output size of the mixing primitive.
        block_size_t block_size;

        // Encryption mode.
        enc_mode_t enc_mode;

        // The mix type of the one-way pass
        mix_t one_way_mix;

        // One-way mix pass implementation.
        mix_func_t one_way_mixpass;

        // Input/output size of the one-way pass mixing primitive.
        block_size_t one_way_block_size;
} ctx_t;

// Context initialization

// Initializes the context `ctx` for encryption purposes with a certain `key` and setting an `iv`.
ctx_err_t ctx_encrypt_init(ctx_t *ctx, enc_mode_t enc_mode, mix_t mix, mix_t one_way_mix,
                           byte *key, size_t size, uint128_t iv, uint8_t fanout);

// Initializes the context `ctx` for keymix-only purposes with a certain `key`.
ctx_err_t ctx_keymix_init(ctx_t *ctx, mix_t mix, byte *key, size_t size, uint8_t fanout);

// Updates the context `ctx` to enable the XOR operation after doing the keymix.
void ctx_enable_encryption(ctx_t *ctx);

// Updates the context `ctx` to disable the XOR operation after doing the keymix.
void ctx_disable_encryption(ctx_t *ctx);

// Updates the context `ctx` to enable the application of IV and counter to the key.
// Must provide an IV.
void ctx_enable_iv_counter(ctx_t *ctx, uint128_t iv);

// Updates the context `ctx` to disable the application of IV and counter to the key.
void ctx_disable_iv_counter(ctx_t *ctx);

// Other utilities

// Get encryption mode name given its type.
char *get_enc_mode_name(enc_mode_t enc_mode);

// Get encryption mode type given its name.
enc_mode_t get_enc_mode_type(char* name);

#endif
