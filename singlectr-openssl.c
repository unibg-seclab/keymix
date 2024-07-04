#include "singlectr-openssl.h"

#include "types.h"
#include <openssl/evp.h>

int singlectr_openssl(byte *seed, byte *out, size_t seed_size) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_256_ecb(), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = seed + seed_size;
        for (; seed < last; seed += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key = seed;
                byte *in  = seed + 2 * SIZE_BLOCK;
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, in, SIZE_BLOCK);
        }

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        return 0;
}
