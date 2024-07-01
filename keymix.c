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

#include "aesni.h"
#include "types.h"
#include "utils.h"

#include "multictr.h"
#include "singlectr.h"

// Mixes the seed into out
int mix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (byte *)malloc(seed_size);

        size_t nof_macros = (seed_size / AES_BLOCK_SIZE) / config->blocks_per_macro;
        // Not immediate rn, but when deriving T+1 seeds consider if it does
        // make a difference switching to something faster than 2 calls to
        // floating-point logs
        // e.g. https://math.stackexchange.com/questions/1627914/smart-way-to-calculate-floorlogx
        // or using GCC builtins
        unsigned int levels = 1 + (unsigned int)(log10(nof_macros) / log10(config->diff_factor));

        // Setup the structure to save the output into out
        memcpy(buffer, seed, seed_size);

        for (unsigned int level = 0; level < levels; level++) {
                int err = (*(config->mixfunc))(buffer, out, seed_size, config->blocks_per_macro);
                D assert(err == 0 && "Encryption error");

                // No swap at the last level, so the output stays in `out`
                if (level == levels - 1) {
                        break;
                }

                // Swap `out`, and put the result in `buffer` for the next
                // iteration
                swap_seed(buffer, out, seed_size, level, config->diff_factor);
        }

        free(buffer);
        return 0;
}

int mix_wrapper(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        int err = mix(seed, out, seed_size, config);
        D assert(err == 0 && "Encryption error");
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

        // Seed dimension (in Bytes)
        // size_t seed_size = 8503056;
        // size_t seed_size = 229582512;
        size_t seed_size = 22369621 * (3 * AES_BLOCK_SIZE); // ~ 1GiB
        printf("Seed has size %zu MiB\n", seed_size / 1024 / 1024);

        byte *seed = checked_malloc(seed_size);
        byte *out  = checked_malloc(seed_size);

        // {function_name, descr, blocks_per_macro, diff_factor}
        mixing_config configs[] = {
            {&multictr, "multictr", 9, 9},      {&recmultictr, "recmultictr", 9, 9},
            {&singlectr, "singlectr", 3, 4},    {&aesni, "aesni (swap 96)", 3, 4},
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
