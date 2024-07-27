#ifndef ENC_H
#define ENC_H

#include "types.h"

typedef struct {
        byte *key;
        size_t key_size;
        mixctrpass_impl_t mixctrpass;
        fanout_t fanout;
        uint128_t iv;
        bool encrypt;
} keymix_ctx_t;

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *secret, size_t size, uint128_t iv,
                      fanout_t fanout);

void ctx_keymix_init(keymix_ctx_t *ctx, mixctr_t mixctr, byte *secret, size_t size,
                     fanout_t fanout);

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
