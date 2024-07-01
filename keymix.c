#include <assert.h>
#include <math.h>
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

// TODO: do something about this global
byte *TMP_BUF;

#include "aesni.h"
#include "types.h"
#include "utils.h"

#include "multictr.h"
#include "singlectr.h"

// Mixes the seed into out
int mix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (byte *)malloc(seed_size);

        size_t nof_macros   = (seed_size / AES_BLOCK_SIZE) / config->blocks_per_macro;
        unsigned int levels = 1 + (unsigned int)(log10(nof_macros) / log10(config->diff_factor));

        // Setup the structure to save data into out
        memcpy(seed, out, seed_size);

        for (unsigned int level = 0; level < levels; level++) {
                // Mixfunc puts the result into buffer, except for recmultictr
                // which puts the result into out
                int err = (*(config->mixfunc))(out, buffer, seed_size, config->blocks_per_macro);
                D assert(err == 0 && "Encryption error");

                // no swap at the last level
                if (level == levels - 1) {
                        break;
                }

                if (config->mixfunc == &recmultictr) {
                        // out -> out
                        swap_seed(out, out, seed_size, level, config->diff_factor);
                } else {
                        // buffer -> out
                        swap_seed(out, buffer, seed_size, level, config->diff_factor);
                }
        }

        free(buffer);
        return 0;
}

int mix_wrapper(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        TMP_BUF = malloc(AES_BLOCK_SIZE * config->blocks_per_macro);
        int err = mix(seed, out, seed_size, config);
        D assert(err == 0 && "Encryption error");
        free(TMP_BUF);
        return err;
}

int main() {

        // todo: rewrite code to test different encryption suites
        // todo: write on a real file
        // todo: recover and check correct parameters
        // todo: apply davies-meyer
        // todo: apply the seed to a file
        // todo: apply the seed at T, T+1, T+2...
        // todo: single-sweep ctr (or rewrite first block) to change seed
        // todo: handle secondary keys (redis?)
        // todo: introduce parallelization as discussed

        // todo: replace usingned int with something else to handle
        // very large seeds (>1GiB)

        //	size_t seed_size = 8503056;
        // size_t seed_size = 229582512;
        size_t seed_size = 22369621 * 48; // in bytes, ~ 1GiB

        printf("Seed has size %zu MiB\n", seed_size / 1024 / 1024);

        byte *seed = checked_malloc(seed_size);
        byte *out  = checked_malloc(seed_size);

        // {function_name, descr, blocks_per_macro, diff_factor}
        mixing_config configs[] = {
            {&multictr, "multictr", 9, 9}, // {&recmultictr, "recmultictr", 9, 9},
            {&singlectr, "singlectr", 3, 4},
            {&aesni, "aesni (swap 96)", 3, 4},
            {&aesni, "aesni (swap 128)", 3, 3},
        };

        unsigned int err = 0;
        for (unsigned int i = 0; i < sizeof(configs) / sizeof(mixing_config); i++) {
                printf("zeroing memory...\n");
                explicit_bzero(seed, seed_size);
                explicit_bzero(out, seed_size);

                if (seed_size <= 3 * AES_BLOCK_SIZE * 3) {
                        print_buffer_hex(seed, seed_size, "seed");
                        print_buffer_hex(out, seed_size, "out");
                }
                unsigned int nof_macros =
                    (seed_size / AES_BLOCK_SIZE) / configs[i].blocks_per_macro;
                unsigned int levels =
                    1 + (unsigned int)(log10(nof_macros) / log10(configs[i].diff_factor));

                printf("nof_macros:\t\t%d\n", nof_macros);
                printf("levels:\t\t\t%d\n", levels);
                printf("%s mixing...\n", configs[i].descr);
                printf("blocks_per_macro:\t%d\n", configs[i].blocks_per_macro);
                printf("diff_factor:\t\t%d\n", configs[i].diff_factor);

                double time = MEASURE({ err = mix_wrapper(seed, out, seed_size, &configs[i]); });

                explicit_bzero(TMP_BUF, AES_BLOCK_SIZE * configs[i].blocks_per_macro);
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
        free(out);
        return err;
}
