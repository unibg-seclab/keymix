#include <math.h>
#include <string.h>

#include "types.h"
#include "utils.h"

// Mixes the seed into out
int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (byte *)checked_malloc(seed_size);

        int err             = 0;
        size_t nof_macros   = seed_size / SIZE_MACRO;
        unsigned int levels = 1 + (unsigned int)(log(nof_macros) / log(config->diff_factor));

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
