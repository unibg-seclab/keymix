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

#define NUM_OF_TESTS 1
#define MINIMUM_SEED_SIZE (8 * SIZE_1MiB)
#define MAXIMUM_SEED_SIZE (10 * SIZE_1MiB)
// #define MAXIMUM_SEED_SIZE (1.9 * SIZE_1GiB)

#define MiB(SIZE) ((double)(SIZE) / 1024 / 1024)

// Note that test_single_keymix covers the case with expansion 1 and threads 1

#define MAX_THREADS 4
#define MAX_EXPANSION 4

#define FOR_EVERY(x, ptr, size) for (__typeof__(*ptr) *x = ptr; x < ptr + size; x++)

#define SAFE_REALLOC(PTR, SIZE)                                                                    \
        PTR = realloc(PTR, SIZE);                                                                  \
        if (PTR == NULL) {                                                                         \
                LOG("Out of memory :(\n");                                                         \
                goto cleanup;                                                                      \
        }

// -------------------------------------------------- Utility functions

void csv_header() {
        printf("seed_size,");        // Seed size in B
        printf("expansion,");        // How many Ts to generate (each seed_size big)
        printf("internal_threads,"); // Number of threads for parallel_keymix, if 1 use keymix
        printf("external_threads,"); // Number of threads to generate the different Ts
        printf("implementation,");   // AES implementation/library used
        printf("diff_factor,");      // Fanout
        printf("time\n");            // Time in ms
}
void csv_line(size_t seed_size, size_t expansion, int internal_threads, int external_threads,
              char *implementation, int diff_factor, double time) {
        printf("%zu,", seed_size);
        printf("%zu,", expansion);
        printf("%d,", internal_threads);
        printf("%d,", external_threads);
        printf("%s,", implementation);
        printf("%d,", diff_factor);
        printf("%.2f\n", time);
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

void setup_valid_internal_threads(size_t diff_factor, int **internal_threads,
                                  size_t *internal_threads_count) {
        *internal_threads_count = 0;

        int thr = 1;

        while (thr <= MAX_THREADS) {
                (*internal_threads_count)++;
                thr *= diff_factor;
        }

        *internal_threads = realloc(*internal_threads, sizeof(int) * *internal_threads_count);

        thr = 1;
        for (int i = 0; i < *internal_threads_count; i++) {
                (*internal_threads)[i] = thr;
                thr *= diff_factor;
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

int main() {
        // Gli unici per cui il nostro schema funzione e ha senso
        size_t diff_factors[]     = {2, 3, 4};
        size_t diff_factors_count = sizeof(diff_factors) / sizeof(__typeof__(*diff_factors));

        byte *seed = NULL;
        byte *out  = NULL;

        size_t *seed_sizes = NULL;
        size_t seed_sizes_count;

        int *internal_threads = NULL;
        size_t internal_threads_count;

        mixing_config configs[3] = {};
        size_t configs_count     = sizeof(configs) / sizeof(__typeof__(*configs));

        LOG("Doing %d tests (each dot = 1 test)\n", NUM_OF_TESTS);

        csv_header();

        FOR_EVERY(diff_p, diff_factors, diff_factors_count) {
                size_t diff_factor = *diff_p;

                setup_seeds(diff_factor, &seed_sizes, &seed_sizes_count);
                setup_configs(diff_factor, configs);
                setup_valid_internal_threads(diff_factor, &internal_threads,
                                             &internal_threads_count);

                FOR_EVERY(size, seed_sizes, seed_sizes_count) {
                        // Setup seed
                        LOG("Testing seed size %zu B (%.2f MiB)\n", *size, MiB(*size));
                        SAFE_REALLOC(seed, *size);

                        FOR_EVERY(config, configs, configs_count) {
                                FOR_EVERY(ithr, internal_threads, internal_threads_count) {
                                        for (int ethr = 1; ethr <= MAX_THREADS; ethr++) {
                                                for (size_t exp = 1; exp <= MAX_EXPANSION; exp++) {
                                                        SAFE_REALLOC(out, exp * (*size));
                                                        test_keymix(seed, out, *size, exp, *ithr,
                                                                    ethr, config);
                                                }
                                        }
                                }
                        }
                }
        }

cleanup:
        free(seed);
        free(out);
        free(seed_sizes);
        free(internal_threads);
        return 0;
}
