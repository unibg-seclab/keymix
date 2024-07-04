#include <math.h>
#include <stddef.h>
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

#include "types.h"
#include "utils.h"

#include "aesni.h"
#include "singlectr-openssl.h"
#include "singlectr-wolfssl.h"

// Mixes the seed into out
int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (byte *)checked_malloc(seed_size);

        int err             = 0;
        size_t nof_macros   = (seed_size / AES_BLOCK_SIZE) / BLOCKS_PER_MACRO;
        unsigned int levels = 1 + (unsigned int)(log10(nof_macros) / log10(config->diff_factor));

        // Setup the structure to save the output into out
        memcpy(buffer, seed, seed_size);

        for (unsigned int level = 0; level < levels; level++) {
                // Step 1: encrypt
                err = (*(config->mixfunc))(buffer, out, seed_size);
                if (err)
                        goto cleanup;

                // Step 2: swap (but not at the last level)
                if (level < levels - 1) {
                        // Swap `out`, and put the result in `buffer` for the next
                        // iteration
                        swap_seed(buffer, out, seed_size, level, config->diff_factor);
                }
        }

cleanup:
        explicit_bzero(buffer, seed_size);
        free(buffer);
        return err;
}

int main() {
        size_t seed_size = 22369621 * (3 * AES_BLOCK_SIZE); // ~ 1GiB
        LOG("Seed has size %zu MiB\n", seed_size / 1024 / 1024);

        byte *seed = checked_malloc(seed_size);
        byte *out  = checked_malloc(seed_size);

        // {function_name, descr, diff_factor}
        mixing_config configs[] = {
            {&singlectr_wolfssl, "singlectr (wolfssl, 96)", 4},
            {&singlectr_openssl, "singlectr (openssl, 96)", 4},
            {&aesni, "aesni (swap 96)", 4},
        };

        unsigned int err = 0;
        for (unsigned int i = 0; i < sizeof(configs) / sizeof(mixing_config); i++) {
                explicit_bzero(seed, seed_size);
                explicit_bzero(out, seed_size);

                unsigned int nof_macros = (seed_size / AES_BLOCK_SIZE) / BLOCKS_PER_MACRO;
                unsigned int levels =
                    1 + (unsigned int)(log10(nof_macros) / log10(configs[i].diff_factor));

                LOG("nof_macros:\t\t%d\n", nof_macros);
                LOG("levels:\t\t\t%d\n", levels);
                LOG("%s mixing...\n", configs[i].descr);
                LOG("blocks_per_macro:\t%d\n", BLOCKS_PER_MACRO);
                LOG("diff_factor:\t\t%d\n", configs[i].diff_factor);

                double time = MEASURE({ err = keymix(seed, out, seed_size, &configs[i]); });

                explicit_bzero(out, seed_size);

                if (err != 0) {
                        LOG("Error occured while encrypting");
                        goto clean;
                }

                unsigned short precision = 2;
                double readable_size     = (double)seed_size / SIZE_1MiB;
                LOG("total time [s]:\t\t%.*lf\n", precision, time / 1000);
                LOG("total size [MiB]:\t%.*lf\n", precision, readable_size);
                LOG("avg. speed [MiB/s]:\t%.*lf\n", precision, readable_size * 1000 / (time));
                LOG("====\n");
        }

clean:
        explicit_bzero(seed, seed_size);
        free(seed);
        free(out);
        return err;
}
