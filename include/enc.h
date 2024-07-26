#ifndef ENC_H
#define ENC_H

#include "types.h"

typedef enum {
        FANOUT2 = 2,
        FANOUT3 = 3,
        FANOUT4 = 4,
} fanout_t;

typedef enum {
        MIXCTRPASS_WOLFSSL,
        MIXCTRPASS_OPENSSL,
        MIXCTRPASS_AESNI,
} mixctrpass_t;

typedef struct {
        byte *key;
        size_t key_size;

        mixctrpass_impl_t mixctrpass;
        fanout_t fanout;
        uint128_t iv;

        bool encrypt;
} keymix_ctx_t;

void ctx_encrypt_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, size_t size,
                      uint128_t iv, fanout_t fanout);

void ctx_keymix_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, size_t size,
                     fanout_t fanout);

int keymix_t(keymix_ctx_t *ctx, byte *out, size_t out_size, uint8_t external_threads,
             uint8_t internal_threads);

#endif
