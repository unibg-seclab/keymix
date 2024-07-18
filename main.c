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

#include "aesni.h"
#include "keymix.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"

int main() {
        // todo: rewrite code to test different encryption suites
        // todo: write on a real file
        // todo: recover and check correct parameters
        // todo: apply davies-meyer
        // todo: apply the seed to a file
        // todo: apply the seed at T, T+1, T+2...
        // todo: single-sweep ctr (or rewrite first block) to change seed
        // todo: handle secondary keys (redis?)

        // todo: replace usingned int with something else to handle
        // very large seeds (>1GiB)

        // Seed dimension (in Bytes)
        // size_t seed_size = 8503056;
        // size_t seed_size = 229582512;
        // size_t seed_size = 22369621 * (3 * AES_BLOCK_SIZE); // ~ 1GiB
        size_t seed_size = SIZE_MACRO * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3 * 3;
        printf("Seed has size %zu MiB\n", seed_size / 1024 / 1024);
        printf("====\n");

        byte *seed = malloc(seed_size);
        byte *out  = malloc(seed_size);
        if (seed == NULL || out == NULL) {
                LOG("Cannot allocate more memory\n");
                goto clean;
        }

        // {function_name, descr, diff_factor}
        mixing_config configs[] = {
            {&wolfssl, 3},
            {&openssl, 3},
            {&aesni, 3},
        };
        char *descr[] = {"wolfssl (128)", "openssl (128)", "aesni (128)"};

        mixing_config mconf    = {&wolfssl, 3};
        unsigned int threads[] = {1, 3, 9, 27, 81};
        for (unsigned int t = 0; t < sizeof(threads) / sizeof(unsigned int); t++) {
                printf("Multi-threaded wolfssl (128) with %d threads\n", threads[t]);
                int pe          = 0;
                int nof_threads = threads[t];
                double time =
                    MEASURE({ pe = parallel_keymix(seed, out, seed_size, &mconf, nof_threads); });
                unsigned short precision = 2;
                double readable_size     = (double)seed_size / SIZE_1MiB;
                printf("total time [s]:\t\t%.*lf\n", precision, time / 1000);
                printf("total size [MiB]:\t%.*lf\n", precision, readable_size);
                printf("avg. speed [MiB/s]:\t%.*lf\n", precision, readable_size * 1000 / time);
                printf("====\n");

                if (pe != 0) {
                        printf("something went wrong %d\n", pe);
                        exit(1);
                }
        }

        unsigned int err = 0;
        for (unsigned int i = 0; i < sizeof(configs) / sizeof(mixing_config); i++) {
                printf("zeroing memory...\n");
                explicit_bzero(seed, seed_size);
                explicit_bzero(out, seed_size);

                if (seed_size <= 48 * 3) {
                        print_buffer_hex(seed, seed_size, "seed");
                        print_buffer_hex(out, seed_size, "out");
                }
                unsigned int nof_macros = seed_size / 48;
                unsigned int levels     = 1 + LOGBASE(nof_macros, configs[i].diff_factor);

                printf("levels:\t\t\t%d\n", levels);
                printf("%s mixing...\n", descr[i]);
                printf("diff_factor:\t\t%d\n", configs[i].diff_factor);

                double time = MEASURE({ err = keymix(seed, out, seed_size, &configs[i]); });

                explicit_bzero(out, seed_size);

                if (err != 0) {
                        printf("Error occured while encrypting");
                        goto clean;
                }

                unsigned short precision = 2;
                double readable_size     = (double)seed_size / SIZE_1MiB;
                printf("total time [s]:\t\t%.*lf\n", precision, time / 1000);
                printf("total size [MiB]:\t%.*lf\n", precision, readable_size);
                printf("avg. speed [MiB/s]:\t%.*lf\n", precision, readable_size * 1000 / (time));
                printf("====\n");
        }

clean:
        explicit_bzero(seed, seed_size);
        free(seed);
        explicit_bzero(out, seed_size);
        free(out);
        return err;
}
