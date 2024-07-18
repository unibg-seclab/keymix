#include "openssl.h"

#include "types.h"
#include <assert.h>
#include <openssl/evp.h>

int openssl(byte *seed, byte *out, size_t seed_size) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_256_ecb(), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = seed + seed_size;
        for (; seed < last; seed += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key        = seed;
                __uint128_t data = *(__uint128_t *)(seed + 2 * SIZE_BLOCK);

                __uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, (byte *)in, SIZE_MACRO);
        }

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        return 0;
}
