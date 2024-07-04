#include "keymix.h"

#include "aesni.h"
#include "singlectr-openssl.h"
#include "singlectr-wolfssl.h"
#include "utils.h"
#include <string.h>

#define NUM_OF_TESTS 2

int main() {
        size_t seed_sizes[] = {
            11184810 * SIZE_MACRO, // ~500 MiB
            22369621 * SIZE_MACRO, // ~1 GiB
        };

        // {function_name, descr, diff_factor}
        mixing_config configs[] = {
            {&singlectr_wolfssl, "wolfssl", 4},
            {&singlectr_openssl, "openssl", 4},
            {&aesni, "aesni", 4},
        };

        byte *seed = NULL;
        byte *out  = NULL;

        for (int i = 0; i < sizeof(seed_sizes) / sizeof(size_t); i++) {
                size_t size = seed_sizes[i];

                LOG("Testing seed size %zu MiB\n", size / 1024 / 1024);

                seed = realloc(seed, size);
                out  = realloc(out, size);
                if (seed == NULL || out == NULL) {
                        LOG("Out of memory :(\n");
                        goto cleanup;
                }

                for (int c = 0; c < sizeof(configs) / sizeof(mixing_config); c++) {
                        mixing_config config = configs[c];
                        LOG("Implementation %s, fanout %d (%d tests): ", config.descr,
                            config.diff_factor, NUM_OF_TESTS);

                        for (int test = 0; test < NUM_OF_TESTS; test++) {
                                double time = MEASURE(keymix(seed, out, size, &config));

                                // Output CSV format
                                // seed_size, implementation, fanout, time [ms]
                                printf("%zu,%s,%d,%f\n", size, config.descr, config.diff_factor,
                                       time);
                                LOG(".");
                        }
                        LOG("\n");
                }
        }

cleanup:
        free(seed);
        free(out);
        return 0;
}
