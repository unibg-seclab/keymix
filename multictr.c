#include "multictr.h"

#include "config.h"
#include "utils.h"
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

int multictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {
        // current max ctr len = 2^8-1
        size_t buffer_size = AES_BLOCK_SIZE * blocks_per_macro;
        byte *buffer       = malloc(buffer_size);
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                printf("AesInit returned: %d\n", err);
                goto cleanup;
        }
        unsigned int macro_offset;

        for (unsigned int u = 0; u < seed_size / (AES_BLOCK_SIZE * blocks_per_macro); u++) {
                macro_offset = u * blocks_per_macro * AES_BLOCK_SIZE;
                unsigned int KEY_OFFSET, IV_OFFSET;
                IV_OFFSET = 2 * AES_BLOCK_SIZE;
                for (unsigned int tblock = 0; tblock < blocks_per_macro / 3; tblock++) {
                        // offset of a new key
                        KEY_OFFSET = macro_offset + tblock * 3 * AES_BLOCK_SIZE;
                        err        = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL,
                                                  AES_ENCRYPTION);
                        if (err != 0) {
                                printf("AesSetKey returned: %d\n", err);
                                goto cleanup;
                        }
                        for (unsigned short b = 0; b < blocks_per_macro; b++) {
                                err = wc_AesEncryptDirect(&aes, buffer,
                                                          seed + KEY_OFFSET + IV_OFFSET);
                                if (err != 0) {
                                        printf("AesEncryptDirect returned: %d\n", err);
                                        goto cleanup;
                                }
                                seed[KEY_OFFSET + IV_OFFSET] += 1;
                        }
                        if (tblock == 0) {
                                // copy
                                memcpy(&out[macro_offset], buffer,
                                       blocks_per_macro * AES_BLOCK_SIZE);
                        } else {
                                // xor
                                memxor(&out[macro_offset], buffer,
                                       blocks_per_macro * AES_BLOCK_SIZE);
                        }
                }
        }
        // remember that outside of this function the result is saved into (byte
        // *out)
cleanup:
        explicit_bzero(buffer, buffer_size);
        free(buffer);
        wc_AesFree(&aes);
        return err ? ERR_ENC : 0;
}

// Note that, for this function, `seed` is both input and output
// The "actual" interface for recmultictr is down, after this one
int recmultictr_inner(byte *seed, size_t seed_size, unsigned int blocks_per_macro, byte *buffer) {
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                printf("AesInit returned: %d\n", err);
                goto cleanup;
        }
        unsigned int MACRO_OFFSET;
        unsigned int IV_OFFSET = 2 * AES_BLOCK_SIZE;
        unsigned int ROUNDS    = seed_size / (AES_BLOCK_SIZE * blocks_per_macro);
        for (unsigned int r = 0; r < ROUNDS; r++) {
                MACRO_OFFSET = r * blocks_per_macro * AES_BLOCK_SIZE;
                unsigned int KEY_OFFSET;
                for (unsigned int tblock = 0; tblock < blocks_per_macro / 3; tblock++) {
                        // offset of a new key
                        KEY_OFFSET = MACRO_OFFSET + tblock * 3 * AES_BLOCK_SIZE;
                        err        = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL,
                                                  AES_ENCRYPTION);
                        if (err != 0) {
                                printf("AesSetKey returned: %d\n", err);
                                goto cleanup;
                        }
                        for (unsigned short b = 0; b < (1 + tblock) * 3; b++) {
                                err = wc_AesEncryptDirect(&aes, buffer,
                                                          seed + KEY_OFFSET + IV_OFFSET);
                                if (err != 0) {
                                        printf("AesEncryptDirect returned: %d\n", err);
                                        goto cleanup;
                                }
                                seed[KEY_OFFSET + IV_OFFSET] += 1;
                        }
                        if (tblock == 0) {
                                // copy
                                memcpy(&seed[MACRO_OFFSET], buffer,
                                       (1 + tblock) * 3 * AES_BLOCK_SIZE);
                        } else {
                                // xor
                                memxor(&seed[MACRO_OFFSET], buffer,
                                       (1 + tblock) * 3 * AES_BLOCK_SIZE);
                        }
                }
        }
cleanup:
        wc_AesFree(&aes);
        return err ? ERR_ENC : 0;
}

int recmultictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {
        size_t buffer_size = AES_BLOCK_SIZE * blocks_per_macro;
        byte *buffer       = malloc(buffer_size);

        memcpy(out, seed, seed_size);
        int err = recmultictr_inner(out, seed_size, blocks_per_macro, buffer);

        explicit_bzero(buffer, buffer_size);
        free(buffer);
        return err;
}
