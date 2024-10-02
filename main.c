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
#include "mix.h"
#include "types.h"
#include "utils.h"

#define SIZE_1MiB (1024 * 1024)

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

        const mix_t *configs = MIX_TYPES;

        // mixing_config mconf = {&wolfssl, 3};
        // uint8_t threads[] = {1, 3, 9, 27, 81};
        // for (uint8_t t = 0; t < sizeof(threads) / sizeof(uint8_t); t++) {
        //         printf("Multi-threaded wolfssl (128) with %d threads\n", threads[t]);
        //         int pe              = 0;
        //         uint8_t nof_threads = threads[t];
        //         double time =
        //             MEASURE({ pe = keymix(get_mix_impl(configs[0]), key, out, key_size, 3, nof_threads); });
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
        for (uint8_t i = 0; i < sizeof(MIX_TYPES) / sizeof(mix_t); i++) {
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
                printf("%s mixing...\n", get_mix_name(configs[i]));
                printf("fanout:\t\t\t%d\n", fanout);

                // Setup global cipher and hash functions
                keymix_ctx_t ctx;
                ctx_keymix_init(&ctx, configs[i], key, key_size, fanout);

                double time = MEASURE({ err = keymix(get_mix_impl(configs[i]), key, out, key_size, fanout, 1); }); // all layers
                // double time = MEASURE({ err = (*get_mix_impl(configs[i]))(key, out, key_size); }); // single layer

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
