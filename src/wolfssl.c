#include "wolfssl.h"

#include "config.h"
#include "utils.h"
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
                D assert(sizeof(in) == SIZE_MACRO);

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

// The following implementation has some problems
// with some dimensions (e.g., fanout 2, 6 levels).
// For now, I'll leave it commented

// int wolfssl(byte *seed, byte *out, size_t seed_size) {
//         Aes aes;
//         int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
//         D if (err) {
//                 LOG("AesInit returned: %d\n", err);
//                 goto cleanup;
//         }

//         unsigned int KEY_OFFSET;
//         unsigned int rounds    = seed_size / (SIZE_BLOCK * BLOCKS_PER_MACRO);
//         unsigned int iv_offset = 2 * SIZE_BLOCK;

//         for (unsigned int r = 0; r < rounds; r++) {
//                 KEY_OFFSET = r * BLOCKS_PER_MACRO * SIZE_BLOCK;
//                 err = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * SIZE_BLOCK, NULL,
//                 AES_ENCRYPTION); D if (err) {
//                         LOG("AesSetKey returned: %d\n", err);
//                         goto cleanup;
//                 }
//                 for (unsigned short b = 0; b < BLOCKS_PER_MACRO; b++) {
//                         err = wc_AesEncryptDirect(&aes, out + KEY_OFFSET + b * SIZE_BLOCK,
//                                                   seed + KEY_OFFSET + iv_offset);
//                         D if (err) {
//                                 LOG("AesEncryptDirect returned: %d\n", err);
//                                 goto cleanup;
//                         }
//                         seed[KEY_OFFSET + iv_offset] += 1;
//                 }
//         }
// cleanup:
//         // remember that outside of this function the result is saved into (byte
//         // *out)
//         wc_AesFree(&aes);
//         return err ? ERR_ENC : 0;
// }
