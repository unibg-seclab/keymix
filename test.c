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

// Note that test_single_keymix covers the case with expansion 1 and threads 1

#define MAX_THREADS 4
#define MAX_EXPANSION 4

// https://stackoverflow.com/questions/78030049/how-do-i-determine-the-type-of-an-element-in-a-struct-in-a-c-macro
#define FOR_EVERY(idx, array)                                                                      \
        for (size_t idx = 0; idx < sizeof(array) / sizeof(__typeof__(*(array))); idx++)

#define SAFE_REALLOC(PTR, SIZE)                                                                    \
        PTR = realloc(PTR, SIZE);                                                                  \
        if (PTR == NULL) {                                                                         \
                LOG("Out of memory :(\n");                                                         \
                goto cleanup;                                                                      \
        }

// -------------------------------------------------- Utility functions

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
        *internal_threads_count = 0; // 1 thread always valid

        int thr = 1;

        // 1 thread is managed directly by the simple keymix
        do {
                thr *= diff_factor;
                (*internal_threads_count)++;
        } while (thr < MAX_THREADS);

        *internal_threads = realloc(*internal_threads, sizeof(int) * *internal_threads_count);
        // We skip thr = 1, because for that we use the non-threaded keymix version
        thr = diff_factor;
        for (int i = 0; i < *internal_threads_count; i++) {
                (*internal_threads)[i] = thr;
                thr *= diff_factor;
        }
}

// -------------------------------------------------- Actual test functions

void test_single_keymix(size_t diff_factor, byte *seed, byte *out, size_t seed_size,
                        mixing_config *config) {

        LOG("[SIMPLE] Implementation %s, fanout %d (%d tests): ", config->descr,
            config->diff_factor, NUM_OF_TESTS);

        for (int test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(keymix(seed, out, seed_size, config));

                printf("%zu,%d,%d,%s,%d,%f\n", seed_size, 1, 1, config->descr, config->diff_factor,
                       time);
                LOG(".");
        }
        LOG("\n");
}

void test_multi_keymix(size_t diff_factor, byte *seed, byte *out, size_t seed_size,
                       size_t expansion, int threads, mixing_config *config) {
        LOG("[THREADED x%zu (%d thr)] Implementation %s, fanout %d (%d tests): ", expansion,
            threads, config->descr, config->diff_factor, NUM_OF_TESTS);

        for (int test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(
                    keymix_t(seed, seed_size, out, expansion * seed_size, config, threads, 0));

                printf("%zu,%zu,%d,%s,%d,%f\n", seed_size, expansion, threads, config->descr,
                       config->diff_factor, time);
                LOG(".");
        }
        LOG("\n");
}

void test_internal_multi_keymix(size_t diff_factor, byte *seed, byte *out, size_t seed_size,
                                int threads, mixing_config *config) {
        LOG("[INTERNALLY THREADED (%d thr)] Implementation %s, fanout %d (%d tests): ", threads,
            config->descr, config->diff_factor, NUM_OF_TESTS);

        for (int test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(parallel_keymix(seed, out, seed_size, config, threads));

                printf("%zu,%d,%d,%s,%d,%f\n", seed_size, 1, threads, config->descr,
                       config->diff_factor, time);
                LOG(".");
        }
        LOG("\n");
}

// -------------------------------------------------- Main loops

int main() {
        // Gli unici per cui il nostro schema funzione e ha senso
        size_t diff_factors[] = {2, 3, 4};
        byte *seed            = NULL;
        byte *out             = NULL;
        size_t *seed_sizes    = NULL;
        size_t seed_sizes_count;
        int *internal_threads = NULL;
        size_t internal_threads_count;

        mixing_config configs[3];

        // Write CSV header
        // Some special cases:
        // - expansion = 1 and threads = 1           => simple keymix
        // - expansion = 1 and threads > 1           => internally threaded keymix
        // - expansion > 1 and threads > 1           => externally threaded keymix
        printf("seed_size,expansion,threads,implementation,diff_factor,time\n");

        FOR_EVERY(d, diff_factors) {
                size_t diff_factor = diff_factors[d];

                setup_seeds(diff_factor, &seed_sizes, &seed_sizes_count);
                setup_configs(diff_factor, configs);
                setup_valid_internal_threads(diff_factor, &internal_threads,
                                             &internal_threads_count);

                for (int i = 0; i < seed_sizes_count; i++) {
                        size_t size = seed_sizes[i];

                        LOG("Testing seed size %zu B (%.2f MiB)\n", size, MiB(size));

                        SAFE_REALLOC(seed, size);

                        FOR_EVERY(c, configs) {
                                SAFE_REALLOC(out, size);
                                test_single_keymix(diff_factor, seed, out, size, &configs[c]);

                                for (int t = 0; t < internal_threads_count; t++) {
                                        int thr = internal_threads[t];
                                        test_internal_multi_keymix(diff_factor, seed, out, size,
                                                                   thr, &configs[c]);
                                }

                                for (int thr = 2; thr <= MAX_THREADS; thr++) {
                                        for (size_t exp = 2; exp <= MAX_EXPANSION; exp++) {
                                                SAFE_REALLOC(out, exp * size);
                                                test_multi_keymix(diff_factor, seed, out, size, exp,
                                                                  thr, &configs[c]);
                                        }
                                }
                        }
                }
        }

cleanup:
        free(seed);
        free(out);
        free(seed_sizes);
        return 0;
}
