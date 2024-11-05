#ifndef CTX_H
#define CTX_H

#include <stdbool.h>
#include <stdint.h>

#include "mix.h"
#include "types.h"

#define KEYMIX_NONCE_SIZE 8
#define KEYMIX_COUNTER_SIZE 8
#define KEYMIX_IV_SIZE KEYMIX_NONCE_SIZE + KEYMIX_COUNTER_SIZE

typedef enum {
        ENC_MODE_CTR,
        ENC_MODE_CTR_OPT,
        ENC_MODE_OFB,
} enc_mode_t;

typedef enum {
        CTX_ERR_NONE,
        CTX_ERR_UNKNOWN_MIX,
        CTX_ERR_MISSING_MIX,
        CTX_ERR_UNKNOWN_ONE_WAY_MIX,
        CTX_ERR_MISSING_ONE_WAY_MIX,
        CTX_ERR_NOT_ONE_WAY,
        CTX_ERR_INCOMPATIBLE_PRIMITIVES,
        CTX_ERR_EQUAL_PRIMITIVES,
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
        mix_impl_t mix;

        // The mix implementation.
        mix_func_t mixpass;

        // The fanout for the shuffle/spread part.
        uint8_t fanout;

        // Marks this context as an encryption context.
        // That is, to do the XOR after the keymix.
        bool encrypt;

        // Input/output size of the mixing primitive.
        block_size_t block_size;

        // Encryption mode.
        enc_mode_t enc_mode;

        // The mix type of the one-way pass.
        mix_impl_t one_way_mix;

        // One-way mix pass implementation.
        mix_func_t one_way_mixpass;

        // Input/output size of the one-way pass mixing primitive.
        block_size_t one_way_block_size;

        // Precomputation of the internal state to optimize execution of the
        // ctr encryption mode. Or store the next key of the ofb encryption
        // mode.
        byte *state;
} ctx_t;

// Context initialization

// Initializes the context `ctx` for encryption purposes with a certain `key` and setting an `iv`.
ctx_err_t ctx_encrypt_init(ctx_t *ctx, enc_mode_t enc_mode, mix_impl_t mix, mix_impl_t one_way_mix,
                           byte *key, size_t size, uint8_t fanout);

// Initializes the context `ctx` for keymix-only purposes with a certain `key`.
ctx_err_t ctx_keymix_init(ctx_t *ctx, mix_impl_t mix, byte *key, size_t size, uint8_t fanout);

// Updates the context `ctx` to enable the XOR operation after doing the keymix.
void ctx_enable_encryption(ctx_t *ctx);

// Updates the context `ctx` to disable the XOR operation after doing the keymix.
void ctx_disable_encryption(ctx_t *ctx);

// Precompute internal state to optimize execution of the ctr encryption mode.
void ctx_precompute_state(ctx_t *ctx);

// Free `ctx` state.
void ctx_free(ctx_t *ctx);

// Other utilities

// Get encryption mode name given its type.
char *get_enc_mode_name(enc_mode_t enc_mode);

// Get encryption mode type given its name.
enc_mode_t get_enc_mode_type(char* name);

#endif
