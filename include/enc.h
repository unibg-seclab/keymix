#ifndef ENC_H
#define ENC_H

#include "types.h"

typedef enum {
        DIFFUSION2 = 2,
        DIFFUSION3 = 3,
        DIFFUSION4 = 4,
} diffusion_t;

typedef enum {
        MIXCTRPASS_WOLFSSL,
        MIXCTRPASS_OPENSSL,
        MIXCTRPASS_AESNI,
} mixctrpass_t;

typedef struct {
        byte *in;
        byte *out;
        size_t size;

        byte *secret;
        size_t secret_size;

        mixctrpass_impl_t mixctrpass;
        diffusion_t diffusion;

        bool encrypt;
} keymix_ctx_t;

void encrypt_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, size_t secret_size,
                  byte *in, byte *out, size_t size, diffusion_t diffusion);

void keymix_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, byte *out, size_t size,
                 diffusion_t diffusion);

#endif
