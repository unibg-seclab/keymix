#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#include "ctx.h"
#include "keymix.h"
#include "log.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"

#if SIZE_MACRO == 16
#define CHUNK_SIZE 8
#else
#define CHUNK_SIZE 16
#endif

#define SIZE_1MiB (1024 * 1024)

// // This is a little hack, because OpenSSL is *painfully* slow when used in
// // multi-threaded environments.
// // https://github.com/openssl/openssl/issues/17064
// // This is defined in mixctr.c
// extern EVP_CIPHER *openssl_aes256ecb;

void print_buffer_hex(byte *buf, size_t size, char *descr) {
        printf("%s\n", descr);
        for (size_t i = 0; i < size; i++) {
                if (i % 16 == 0) {
                        printf("|");
                }
                printf("%02x", buf[i]);
        }
        printf("|\n");
}

int main() {
        uint8_t fanout = SIZE_MACRO / CHUNK_SIZE;
        size_t key_size = SIZE_MACRO;
        while (key_size < 256 * SIZE_1MiB) {
                key_size *= fanout;
        }
        printf("Key has size %zu MiB\n", key_size / SIZE_1MiB);
        printf("====\n");

        byte *key = malloc(key_size);
        byte *out = malloc(key_size);
        if (key == NULL || out == NULL) {
                _log(LOG_DEBUG, "Cannot allocate more memory\n");
                goto clean;
        }

        mixctr_t configs[] = {
#if SIZE_MACRO == 16
                // 128-bit block size
                MIXCTR_OPENSSL_DAVIES_MEYER_128,
                MIXCTR_WOLFCRYPT_DAVIES_MEYER_128,
#elif SIZE_MACRO == 32
                // 256-bit block size
                MIXCTR_OPENSSL_SHA3_256,
                MIXCTR_OPENSSL_BLAKE2S,
                MIXCTR_WOLFCRYPT_SHA3_256,
                MIXCTR_WOLFCRYPT_BLAKE2S,
                MIXCTR_BLAKE3_BLAKE3,
#elif SIZE_MACRO == 48
                // 384-bit block size
                MIXCTR_AESNI,
                MIXCTR_OPENSSL,
                MIXCTR_WOLFSSL,
#elif SIZE_MACRO == 64
                // 512-bit block size
                MIXCTR_OPENSSL_SHA3_512,
                MIXCTR_OPENSSL_BLAKE2B,
                MIXCTR_WOLFCRYPT_SHA3_512,
                MIXCTR_WOLFCRYPT_BLAKE2B,
#endif
#if SIZE_MACRO <= 48 /* 384-bit internal state */
                MIXCTR_XKCP_XOODYAK,
#endif
#if SIZE_MACRO <= 192 /* 1600-bit internal state */
                MIXCTR_OPENSSL_SHAKE128,
                MIXCTR_WOLFCRYPT_SHAKE128,
                MIXCTR_XKCP_TURBOSHAKE_128,
                MIXCTR_XKCP_KANGAROOTWELVE,
                MIXCTR_OPENSSL_SHAKE256,
                MIXCTR_WOLFCRYPT_SHAKE256,
                MIXCTR_XKCP_TURBOSHAKE_256,
#endif
        };
        char *descr[] = {
#if SIZE_MACRO == 16
                // 128-bit block size
                "openssl davies-meyer (128)",
                "wolfcrypt davies-meyer (128)",
#elif SIZE_MACRO == 32
                // 256-bit block size
                "openssl sha3 (256)",
                "openssl blake2s (256)",
                "wolfcrypt sha3 (256)",
                "wolfcrypt blake2s (256)",
                "blake3 blake3 (256)",
#elif SIZE_MACRO == 48
                // 384-bit block size
                "aes-ni mixctr (384)",
                "openssl mixctr (384)",
                "wolfcrypt mixctr (384)",
#elif SIZE_MACRO == 64
                // 512-bit block size
                "openssl sha3 (512)",
                "openssl blake2b (512)",
                "wolfcrypt sha3 (512)",
                "wolfcrypt blake2b (512)",
#endif
#if SIZE_MACRO <= 48 /* 384-bit internal state */
                "xkcp xoodyak",
#endif
#if SIZE_MACRO <= 192 /* 1600-bit internal state */
                "openssl shake128",
                "wolfcrypt shake128",
                "xkcp turboshake128",
                "xkcp kangarootwelve",
                "openssl shake256",
                "wolfcrypt shake256",
                "xkcp turboshake256",
#endif
        };

        // // Setup global OpenSSL cipher
        // openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);

        // mixing_config mconf = {&wolfssl, 3};
        // uint8_t threads[] = {1, 3, 9, 27, 81};
        // for (uint8_t t = 0; t < sizeof(threads) / sizeof(uint8_t); t++) {
        //         printf("Multi-threaded wolfssl (128) with %d threads\n", threads[t]);
        //         int pe              = 0;
        //         uint8_t nof_threads = threads[t];
        //         double time =
        //             MEASURE({ pe = keymix(get_mixctr_impl(configs[0]), key, out, key_size, 3, nof_threads); });
        //         uint8_t precision    = 2;
        //         double readable_size = (double)key_size / SIZE_1MiB;
        //         printf("total time [s]:\t\t%.*lf\n", precision, time / 1000);
        //         printf("total size [MiB]:\t%.*lf\n", precision, readable_size);
        //         printf("avg. speed [MiB/s]:\t%.*lf\n", precision, readable_size * 1000 / time);
        //         printf("====\n");

        //         if (pe != 0) {
        //                 printf("something went wrong %d\n", pe);
        //                 exit(1);
        //         }
        // }

        int err = 0;
        for (uint8_t i = 0; i < sizeof(configs) / sizeof(mixctr_t); i++) {
                printf("zeroing memory...\n");
                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);

                if (key_size <= SIZE_MACRO * fanout) {
                        print_buffer_hex(key, key_size, "key");
                        print_buffer_hex(out, key_size, "out");
                }
                uint64_t nof_macros = key_size / SIZE_MACRO;
                uint8_t levels      = 1 + LOGBASE(nof_macros, fanout);

                printf("levels:\t\t\t%d\n", levels);
                printf("%s mixing...\n", descr[i]);
                printf("fanout:\t\t\t%d\n", fanout);

                // Setup global cipher and hash functions
                keymix_ctx_t ctx;
                ctx_keymix_init(&ctx, configs[i], key, key_size, fanout);

                double time = MEASURE({ err = keymix(get_mixctr_impl(configs[i]), key, out, key_size, fanout, 1); }); // all layers
                // double time = MEASURE({ err = (*get_mixctr_impl(configs[i]))(key, out, key_size); }); // single layer

                explicit_bzero(out, key_size);

                if (err != 0) {
                        printf("Error occured while encrypting");
                        goto clean;
                }

                uint8_t precision    = 2;
                double readable_size = (double)key_size / SIZE_1MiB;
                printf("total time [s]:\t\t%.*lf\n", precision, time / 1000);
                printf("total size [MiB]:\t%.*lf\n", precision, readable_size);
                printf("avg. speed [MiB/s]:\t%.*lf\n", precision, readable_size * 1000 / (time));
                printf("====\n");
        }

clean:
        explicit_bzero(key, key_size);
        free(key);
        explicit_bzero(out, key_size);
        free(out);
        return err;
}
