#include "wolfssl.h"

#include "config.h"
#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

int wolfssl(byte *seed, byte *out, size_t seed_size) {
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err)
                goto cleanup;

        byte *last = seed + seed_size;
        for (; seed < last; seed += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key        = seed;
                __uint128_t data = *(__uint128_t *)(seed + 2 * SIZE_BLOCK);
                __uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);

                err = wc_AesSetKey(&aes, key, 2 * SIZE_BLOCK, NULL, AES_ENCRYPTION);
                if (err)
                        goto cleanup;

                for (int b = 0; b < 3; b++) {
                        err = wc_AesEncryptDirect(&aes, out + b * SIZE_BLOCK, (byte *)(in + b));
                        if (err)
                                goto cleanup;
                }
        }

cleanup:
        wc_AesFree(&aes);
        return err;
}
