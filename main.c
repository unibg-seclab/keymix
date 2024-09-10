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

#include "keymix.h"
#include "log.h"
#include "mixctr.h"
#include "types.h"
#include "utils.h"

#define SIZE_1MiB (1024 * 1024)

// This is a little hack, because OpenSSL is *painfully* slow when used in
// multi-threaded environments.
// https://github.com/openssl/openssl/issues/17064
// This is defined in mixctr.c
extern EVP_CIPHER *openssl_aes256ecb;

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
        size_t key_size = SIZE_MACRO * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3;
        printf("Key has size %zu MiB\n", key_size / 1024 / 1024);
        printf("====\n");

        byte *key = malloc(key_size);
        byte *out = malloc(key_size);
        if (key == NULL || out == NULL) {
                _log(LOG_DEBUG, "Cannot allocate more memory\n");
                goto clean;
        }

        mixctrpass_impl_t configs[] = {
                get_mixctr_impl(MIXCTR_SHA3_512),
        };
        char *descr[] = {"sha3 (512)",};

        // Setup global OpenSSL cipher
        openssl_aes256ecb = EVP_CIPHER_fetch(NULL, "AES-256-ECB", NULL);

        // mixing_config mconf = {&wolfssl, 3};
        // uint8_t threads[] = {1, 3, 9, 27, 81};
        // for (uint8_t t = 0; t < sizeof(threads) / sizeof(uint8_t); t++) {
        //         printf("Multi-threaded wolfssl (128) with %d threads\n", threads[t]);
        //         int pe              = 0;
        //         uint8_t nof_threads = threads[t];
        //         double time =
        //             MEASURE({ pe = keymix(configs[0], key, out, key_size, 3, nof_threads); });
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
        for (uint8_t i = 0; i < 1; i++) {
                printf("zeroing memory...\n");
                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);

                if (key_size <= 48 * 3) {
                        print_buffer_hex(key, key_size, "key");
                        print_buffer_hex(out, key_size, "out");
                }
                uint64_t nof_macros = key_size / 48;
                uint8_t levels      = 1 + LOGBASE(nof_macros, 3);

                printf("levels:\t\t\t%d\n", levels);
                printf("%s mixing...\n", descr[i]);
                printf("fanout:\t\t%d\n", 3);

                double time = MEASURE({ err = keymix(configs[i], key, out, key_size, 3, 1); });

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
