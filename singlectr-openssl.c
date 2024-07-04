#include "singlectr-openssl.h"

#include "types.h"
#include <openssl/evp.h>
#include <wolfssl/wolfcrypt/aes.h>

int singlectr_openssl(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_aes_256_ecb(), NULL, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outl;

        byte *last = seed + seed_size;
        for (; seed < last; seed += 3 * AES_BLOCK_SIZE, out += 3 * AES_BLOCK_SIZE) {
                byte *key = seed;
                byte *in  = seed + 2 * AES_BLOCK_SIZE;
                EVP_EncryptInit(ctx, NULL, key, NULL);
                EVP_EncryptUpdate(ctx, out, &outl, in, AES_BLOCK_SIZE);
        }

        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);

        return 0;
}
