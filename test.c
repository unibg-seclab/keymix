#include "keymix.h"

#include "aesni.h"
#include "keymix_t.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"
#include <math.h>
#include <string.h>
#include <time.h>

// -------------------------------------------------- Configure tests

#define NUM_OF_TESTS 20
#define MINIMUM_SEED_SIZE (8 * SIZE_1MiB)
#define MAXIMUM_SEED_SIZE (1.9 * SIZE_1GiB)

#define MiB(SIZE) ((double)(SIZE) / 1024 / 1024)
#define MAX_EXPANSION 20

#define DO_EXPANSION_TESTS
#define DO_ENCRYPTION_TESTS

#define FOR_EVERY(x, ptr, size) for (__typeof__(*ptr) *x = ptr; x < ptr + size; x++)

#define SAFE_REALLOC(PTR, SIZE)                                                                    \
        PTR = realloc(PTR, SIZE);                                                                  \
        if (PTR == NULL) {                                                                         \
                LOG("Out of memory :(\n");                                                         \
                goto cleanup;                                                                      \
        }

// -------------------------------------------------- Utility functions

FILE *fout;

void csv_header() {
        fprintf(fout, "seed_size,"); // Seed size in B
        fprintf(fout, "expansion,"); // How many Ts to generate (each seed_size big)
        fprintf(fout,
                "internal_threads,"); // Number of threads for parallel_keymix, if 1 use keymix
        fprintf(fout, "external_threads,"); // Number of threads to generate the different Ts
        fprintf(fout, "implementation,");   // AES implementation/library used
        fprintf(fout, "diff_factor,");      // Fanout
        fprintf(fout, "time\n");            // Time in ms
}
void csv_line(size_t seed_size, size_t expansion, int internal_threads, int external_threads,
              char *implementation, int diff_factor, double time) {
        fprintf(fout, "%zu,", seed_size);
        fprintf(fout, "%zu,", expansion);
        fprintf(fout, "%d,", internal_threads);
        fprintf(fout, "%d,", external_threads);
        fprintf(fout, "%s,", implementation);
        fprintf(fout, "%d,", diff_factor);
        fprintf(fout, "%.2f\n", time);
}

size_t first_x_that_surpasses(double bar, size_t diff_factor) {
        size_t x = 0;
        size_t size;
        do {
                x++;
                size = SIZE_MACRO * pow(diff_factor, x);
        } while (size < bar);

        return x;
}

void setup_seeds(size_t diff_factor, size_t **seed_sizes, size_t *seed_sizes_count) {
        size_t min_x = first_x_that_surpasses(MINIMUM_SEED_SIZE, diff_factor);
        size_t max_x = first_x_that_surpasses(MAXIMUM_SEED_SIZE, diff_factor);

        *seed_sizes_count = max_x + 1 - min_x;
        *seed_sizes       = realloc(*seed_sizes, *seed_sizes_count * sizeof(size_t));

        for (size_t x = min_x; x <= max_x; x++) {
                (*seed_sizes)[x - min_x] = SIZE_MACRO * pow(diff_factor, x);
        }
}

void setup_configs(size_t diff_factor, mixing_config *configs) {
        configs[0].diff_factor = diff_factor;
        configs[0].descr       = "wolfssl";
        configs[0].mixfunc     = &wolfssl;

        configs[1].diff_factor = diff_factor;
        configs[1].descr       = "openssl";
        configs[1].mixfunc     = &openssl;

        configs[2].diff_factor = diff_factor;
        configs[2].descr       = "intel (aesni)";
        configs[2].mixfunc     = &aesni;
}

void setup_valid_internal_threads(size_t diff_factor, int internal_threads[],
                                  size_t *internal_threads_count) {
        // Diff factors can be only one of 3, so we can just wing a switch
        // Just be sure to keep the maximum reasonable

        switch (diff_factor) {
        case 2:
                *internal_threads_count = 5;
                internal_threads[0]     = 1;
                internal_threads[1]     = 2;
                internal_threads[2]     = 4;
                internal_threads[3]     = 8;
                internal_threads[4]     = 16;
                break;
        case 3:
                *internal_threads_count = 3;
                internal_threads[0]     = 1;
                internal_threads[1]     = 3;
                internal_threads[2]     = 9;
                break;
        case 4:
                *internal_threads_count = 3;
                internal_threads[0]     = 1;
                internal_threads[1]     = 4;
                internal_threads[2]     = 16;
                break;
        }
}

// -------------------------------------------------- Actual test functions

void test_keymix(byte *seed, byte *out, size_t seed_size, size_t expansion, int internal_threads,
                 int external_threads, mixing_config *config) {
        LOG("[TEST (i=%d, e=%d)] %s, fanout %d, expansion %zu: ", internal_threads,
            external_threads, config->descr, config->diff_factor, expansion);

        for (int test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(keymix_t(seed, seed_size, out, expansion * seed_size, config,
                                               external_threads, internal_threads, 0));
                csv_line(seed_size, expansion, internal_threads, external_threads, config->descr,
                         config->diff_factor, time);
                LOG(".");
        }
        LOG("\n");
}

// -------------------------------------------------- Main loops

int main(int argc, char *argv[]) {
        if (argc < 3) {
                LOG("Usage:\n");
                LOG("  test [EXP OUTPUT] [ENC OUTPUT]\n");
                return 1;
        }

        // Gli unici per cui il nostro schema funzione e ha senso
        size_t diff_factors[]     = {2, 3, 4};
        size_t diff_factors_count = sizeof(diff_factors) / sizeof(__typeof__(*diff_factors));

        byte *seed = NULL;
        byte *out  = NULL;

        size_t *seed_sizes = NULL;
        size_t seed_sizes_count;

        size_t external_threads[] = {1, 2, 4, 8, 16};
        size_t external_threads_count =
            sizeof(external_threads) / sizeof(__typeof__(*external_threads));

        // There are never no more than 5 internal threads' values
        int internal_threads[5] = {0, 0, 0, 0, 0};
        size_t internal_threads_count;

        mixing_config configs[3] = {};
        size_t configs_count     = sizeof(configs) / sizeof(__typeof__(*configs));

#ifdef DO_EXPANSION_TESTS
        LOG("Doing %d tests (each dot = 1 test)\n", NUM_OF_TESTS);

        fout = fopen(argv[1], "w");
        csv_header();

        FOR_EVERY(diff_p, diff_factors, diff_factors_count) {
                size_t diff_factor = *diff_p;

                setup_seeds(diff_factor, &seed_sizes, &seed_sizes_count);
                setup_configs(diff_factor, configs);
                setup_valid_internal_threads(diff_factor, internal_threads,
                                             &internal_threads_count);

                FOR_EVERY(size, seed_sizes, seed_sizes_count) {
                        // Setup seed
                        LOG("Testing seed size %zu B (%.2f MiB)\n", *size, MiB(*size));
                        SAFE_REALLOC(seed, *size);

                        FOR_EVERY(config, configs, configs_count)
                        FOR_EVERY(ithr, internal_threads, internal_threads_count)
                        FOR_EVERY(ethr, external_threads, external_threads_count)
                        for (size_t exp = 1; exp <= MAX_EXPANSION; exp++) {
                                SAFE_REALLOC(out, exp * (*size));
                                test_keymix(seed, out, *size, exp, *ithr, *ethr, config);
                        }
                }
        }

        fclose(fout);
        fout = NULL;
#endif

#ifdef DO_ENCRYPTION_TESTS
        fout = fopen(argv[2], "w");

        fclose(fout);
        fout = NULL;
#endif

cleanup:
        if (fout)
                fclose(fout);
        free(seed);
        free(out);
        free(seed_sizes);
        return 0;
}
