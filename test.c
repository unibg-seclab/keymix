#include "keymix.h"

#include "aesni.h"
#include "singlectr-openssl.h"
#include "singlectr-wolfssl.h"
#include "types.h"
#include "utils.h"
#include <math.h>
#include <string.h>

#define NUM_OF_TESTS 1
#define MINIMUM_SEED_SIZE (8 * SIZE_1MiB)
#define MAXIMUM_SEED_SIZE (1.9 * SIZE_1GiB)

#define MiB(SIZE) ((double)(SIZE) / 1024 / 1024)

size_t first_x_that_surpasses(double bar, size_t diff_factor) {
        size_t x = 0;
        size_t size;
        do {
                x++;
                size = SIZE_MACRO * pow(diff_factor, x);
        } while (size < bar);

        return x;
}

int main() {
        // Gli unici per cui il nostro schema funzione e ha senso
        size_t diff_factors[] = {2, 3, 4};
        byte *seed            = NULL;
        byte *out             = NULL;
        size_t *seed_sizes    = NULL;

        // Write CSV header
        printf("seed_size,implementation,diff_factor,time\n");

        for (int d = 0; d < sizeof(diff_factors) / sizeof(size_t); d++) {
                size_t diff_factor = diff_factors[d];

                size_t min_x = first_x_that_surpasses(MINIMUM_SEED_SIZE, diff_factor);
                size_t max_x = first_x_that_surpasses(MAXIMUM_SEED_SIZE, diff_factor);

                size_t seed_sizes_count = max_x + 1 - min_x;
                seed_sizes              = realloc(seed_sizes, seed_sizes_count * sizeof(size_t));

                for (size_t x = min_x; x <= max_x; x++) {
                        seed_sizes[x - min_x] = SIZE_MACRO * pow(diff_factor, x);
                }

                mixing_config configs[] = {
                    {&singlectr_wolfssl, "wolfssl", diff_factor},
                    {&singlectr_openssl, "openssl", diff_factor},
                    {&aesni, "aesni", diff_factor},
                };

                for (int i = 0; i < seed_sizes_count; i++) {
                        size_t size = seed_sizes[i];

                        LOG("Testing seed size %zu B (%.2f MiB)\n", size, MiB(size));

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
                                        printf("%zu,%s,%d,%f\n", size, config.descr,
                                               config.diff_factor, time);
                                        LOG(".");
                                }
                                LOG("\n");
                        }
                }
        }

cleanup:
        free(seed);
        free(out);
        free(seed_sizes);
        return 0;
}
