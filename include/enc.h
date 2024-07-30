#ifndef ENC_H
#define ENC_H

#include "types.h"

typedef struct {
        byte *key;
        size_t key_size;
        mixctrpass_impl_t mixctrpass;
        fanout_t fanout;
        uint128_t iv;

        bool do_xor;
        bool do_iv_counter;
} keymix_ctx_t;

// Context initializatino

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *secret, size_t size, uint128_t iv,
                      fanout_t fanout);

void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *secret, size_t size,
                     fanout_t fanout);

inline void ctx_enable_xor(keymix_ctx_t *ctx) { ctx->do_xor = true; }
inline void ctx_disable_xor(keymix_ctx_t *ctx) { ctx->do_xor = false; }

inline void ctx_enable_iv_counter(keymix_ctx_t *ctx, uint128_t iv) {
        ctx->do_iv_counter = true;
        ctx->iv            = iv;
}
inline void ctx_disable_iv_counter(keymix_ctx_t *ctx) {
        ctx->do_iv_counter = false;
        ctx->iv            = 0;
}

// Callable functions

int keymix_t(keymix_ctx_t *ctx, byte *out, size_t out_size, uint8_t external_threads,
             uint8_t internal_threads);

int keymix_ex(keymix_ctx_t *ctx, byte *out, size_t out_size, uint8_t external_threads,
              uint8_t internal_threads, uint128_t starting_counter);

int encrypt(keymix_ctx_t *ctx, byte *in, byte *out, size_t size);

int encrypt_t(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
              uint8_t internal_threads);

int encrypt_ex(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t external_threads,
               uint8_t internal_threads, uint128_t starting_counter);

#endif
