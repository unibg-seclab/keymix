#include "enc.h"

#include "aesni.h"
#include "openssl.h"
#include "wolfssl.h"
#include <stdlib.h>

inline mixctrpass_impl_t get_impl(mixctrpass_t name) {
        switch (name) {
        case MIXCTRPASS_WOLFSSL:
                return &wolfssl;
        case MIXCTRPASS_OPENSSL:
                return &openssl;
        case MIXCTRPASS_AESNI:
                return &aesni;
        }
}

void encrypt_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, size_t secret_size,
                  byte *in, byte *out, size_t size, diffusion_t diffusion) {
        ctx->in   = in;
        ctx->out  = out;
        ctx->size = size;

        ctx->secret      = secret;
        ctx->secret_size = secret_size;

        ctx->mixctrpass = get_impl(mixctrpass);
        ctx->diffusion  = diffusion;
        ctx->encrypt    = true;
}

void keymix_init(keymix_ctx_t *ctx, mixctrpass_t mixctrpass, byte *secret, byte *out, size_t size,
                 diffusion_t diffusion) {
        ctx->in   = NULL;
        ctx->out  = out;
        ctx->size = size;

        ctx->secret      = secret;
        ctx->secret_size = size;

        ctx->mixctrpass = get_impl(mixctrpass);
        ctx->diffusion  = diffusion;
        ctx->encrypt    = false;
}
