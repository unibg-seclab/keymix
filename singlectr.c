#include "singlectr.h"

#include "config.h"
#include "utils.h"
#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

int singlectr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {
        D assert(blocks_per_macro == 3);

        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                err = ERR_ENC;
                printf("AesInit returned: %d\n", err);
                goto cleanup;
        }
        unsigned int KEY_OFFSET;
        unsigned int rounds    = seed_size / (AES_BLOCK_SIZE * blocks_per_macro);
        unsigned int iv_offset = 2 * AES_BLOCK_SIZE;

        for (unsigned int r = 0; r < rounds; r++) {
                KEY_OFFSET = r * blocks_per_macro * AES_BLOCK_SIZE;
                err =
                    wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
                if (err != 0) {
                        err = ERR_ENC;
                        printf("AesSetKey returned: %d\n", err);
                        goto cleanup;
                }
                for (unsigned short b = 0; b < blocks_per_macro; b++) {
                        err = wc_AesEncryptDirect(&aes, out + KEY_OFFSET + b * AES_BLOCK_SIZE,
                                                  seed + KEY_OFFSET + iv_offset);
                        if (err != 0) {
                                printf("AesEncryptDirect returned: %d\n", err);
                                err = ERR_ENC;
                                goto cleanup;
                        }
                        seed[KEY_OFFSET + iv_offset] += 1;
                }
        }
cleanup:
        // remember that outside of this function the result is saved into (byte
        // *out)
        wc_AesFree(&aes);
        return err;
}
