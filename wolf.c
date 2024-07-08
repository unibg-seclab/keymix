#include "wolf.h"

#include "config.h"
#include "utils.h"
#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

int wolf(byte *seed, byte *out, size_t seed_size) {
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                err = ERR_ENC;
                printf("AesInit returned: %d\n", err);
                goto cleanup;
        }
        unsigned int KEY_OFFSET;
        unsigned int rounds    = seed_size / 48;
        unsigned int iv_offset = 32;

        for (unsigned int r = 0; r < rounds; r++) {
                KEY_OFFSET = r * 48;
                err        = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 32, NULL, AES_ENCRYPTION);
                if (err != 0) {
                        err = ERR_ENC;
                        printf("AesSetKey returned: %d\n", err);
                        goto cleanup;
                }
                for (unsigned short b = 0; b < 3; b++) {
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
