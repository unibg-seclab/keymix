#include "wolfssl.h"

#include <assert.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "config.h"

int wolfssl(byte *seed, byte *out, size_t seed_size) {
        Aes aes;
        wc_AesInit(&aes, NULL, INVALID_DEVID);

        byte *last = seed + seed_size;
        for (; seed < last; seed += SIZE_MACRO, out += SIZE_MACRO) {
                byte *key      = seed;
                uint128_t data = *(uint128_t *)(seed + 2 * SIZE_BLOCK);
                uint128_t in[] = {data, data + 1, data + 2};
                if (DEBUG)
                        assert(sizeof(in) == SIZE_MACRO);

                wc_AesSetKey(&aes, key, 2 * SIZE_BLOCK, NULL, AES_ENCRYPTION);

                for (uint8_t b = 0; b < 3; b++) {
                        wc_AesEncryptDirect(&aes, out + b * SIZE_BLOCK, (byte *)(in + b));
                }
        }

cleanup:
        wc_AesFree(&aes);
        return 0;
}
