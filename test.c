#include <math.h>
#include <string.h>
#include <time.h>

#include "aesni.h"
#include "enc.h"
#include "log.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"

// -------------------------------------------------- Configure tests

#define NUM_OF_TESTS 20
#define MINIMUM_SEED_SIZE (8 * SIZE_1MiB)
#define MAXIMUM_SEED_SIZE (1.9 * SIZE_1GiB)

#define MAX_EXPANSION 20

#define DO_EXPANSION_TESTS
#define DO_ENCRYPTION_TESTS

#define FOR_EVERY(x, ptr, size) for (__typeof__(*ptr) *x = ptr; x < ptr + size; x++)

#define SAFE_REALLOC(PTR, SIZE)                                                                    \
        PTR = realloc(PTR, SIZE);                                                                  \
        if (PTR == NULL) {                                                                         \
                _log(LOG_INFO, "Out of memory :(\n");                                              \
                goto cleanup;                                                                      \
        }

// -------------------------------------------------- Utility functions

inline double MiB(size_t size) { return (double)size / 1024 / 1024; }

FILE *fout;

void csv_header() {
        fprintf(fout, "seed_size,"); // Seed size in B
        fprintf(fout, "expansion,"); // How many Ts to generate (each seed_size big)
        fprintf(fout,
                "internal_threads,");       // Number of internal threads
        fprintf(fout, "external_threads,"); // Number of threads to generate the different Ts
        fprintf(fout, "implementation,");   // AES implementation/library used
        fprintf(fout, "diff_factor,");      // Fanout
        fprintf(fout, "time\n");            // Time in ms
        fflush(fout);
}
void csv_line(size_t seed_size, uint64_t expansion, uint8_t internal_threads,
              uint8_t external_threads, char *implementation, uint8_t diff_factor, double time) {
        fprintf(fout, "%zu,", seed_size);
        fprintf(fout, "%zu,", expansion);
        fprintf(fout, "%d,", internal_threads);
        fprintf(fout, "%d,", external_threads);
        fprintf(fout, "%s,", implementation);
        fprintf(fout, "%d,", diff_factor);
        fprintf(fout, "%.2f\n", time);
        fflush(fout);
}

uint8_t first_x_that_surpasses(double bar, uint8_t diff_factor) {
        uint8_t x = 0;
        size_t size;
        do {
                x++;
                size = SIZE_MACRO * pow(diff_factor, x);
        } while (size < bar);

        return x;
}

void setup_seeds(uint8_t diff_factor, size_t **seed_sizes, uint8_t *seed_sizes_count) {
        uint8_t min_x = first_x_that_surpasses(MINIMUM_SEED_SIZE, diff_factor);
        uint8_t max_x = first_x_that_surpasses(MAXIMUM_SEED_SIZE, diff_factor);

        *seed_sizes_count = max_x + 1 - min_x;
        *seed_sizes       = realloc(*seed_sizes, *seed_sizes_count * sizeof(size_t));

        for (uint8_t x = min_x; x <= max_x; x++) {
                (*seed_sizes)[x - min_x] = SIZE_MACRO * pow(diff_factor, x);
        }
}

void setup_configs(uint8_t diff_factor, mixing_config *configs) {
        configs[0].diff_factor = diff_factor;
        configs[0].mixfunc     = &wolfssl;

        configs[1].diff_factor = diff_factor;
        configs[1].mixfunc     = &openssl;

        configs[2].diff_factor = diff_factor;
        configs[2].mixfunc     = &aesni;
}

void setup_valid_internal_threads(uint8_t diff_factor, uint8_t internal_threads[],
                                  uint8_t *internal_threads_count) {
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

void test_keymix(keymix_ctx_t *ctx, byte *out, uint64_t expansion, uint8_t internal_threads,
                 uint8_t external_threads) {
        char *impl = "(unspecified)";
        if (ctx->mixctrpass == &aesni) {
                impl = "aesni";
        } else if (ctx->mixctrpass == &openssl) {
                impl = "openssl";
        } else if (ctx->mixctrpass == &wolfssl) {
                impl = "wolfssl";
        }
        _log(LOG_INFO, "[TEST (i=%d, e=%d)] %s, fanout %d, expansion %zu: ", internal_threads,
             external_threads, impl, ctx->fanout, expansion);

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(keymix_t(ctx, out, expansion * ctx->key_size,
                                               external_threads, internal_threads));
                csv_line(ctx->key_size, expansion, internal_threads, external_threads, impl,
                         ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void test_enc(keymix_ctx_t *ctx, byte *in, byte *out, uint64_t expansion, uint8_t internal_threads,
              uint8_t external_threads) {
        char *impl = "(unspecified)";
        if (ctx->mixctrpass == &aesni) {
                impl = "aesni";
        } else if (ctx->mixctrpass == &openssl) {
                impl = "openssl";
        } else if (ctx->mixctrpass == &wolfssl) {
                impl = "wolfssl";
        }
        _log(LOG_INFO, "[TEST (i=%d, e=%d)] %s, fanout %d, expansion %zu: ", internal_threads,
             external_threads, impl, ctx->fanout, expansion);

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(encrypt_t(ctx, in, out, expansion * ctx->key_size,
                                                external_threads, internal_threads));
                csv_line(ctx->key_size, expansion, internal_threads, external_threads, impl,
                         ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

// -------------------------------------------------- Main loops

int main(int argc, char *argv[]) {
        if (argc < 3) {
                _log(LOG_INFO, "Usage:\n");
                _log(LOG_INFO, "  test [EXP OUTPUT] [ENC OUTPUT]\n");
                return 1;
        }

        // Gli unici per cui il nostro schema funzione e ha senso
        uint8_t fanouts[]     = {2, 3, 4};
        uint8_t fanouts_count = sizeof(fanouts) / sizeof(__typeof__(*fanouts));

        byte *seed = NULL;
        byte *out  = NULL;
        byte *in   = NULL;

        size_t *seed_sizes = NULL;
        uint8_t seed_sizes_count;

        uint8_t external_threads[] = {1, 2, 4, 8, 16};
        uint8_t external_threads_count =
            sizeof(external_threads) / sizeof(__typeof__(*external_threads));

        // There are never no more than 5 internal threads' values
        uint8_t internal_threads[5] = {0, 0, 0, 0, 0};
        uint8_t internal_threads_count;

        keymix_ctx_t ctx;

#ifdef DO_EXPANSION_TESTS
        _log(LOG_INFO, "Doing %d tests (each dot = 1 test)\n", NUM_OF_TESTS);

        fout = fopen(argv[1], "w");
        csv_header();

        FOR_EVERY(diff_p, fanouts, fanouts_count) {
                uint8_t fanout = *diff_p;

                setup_seeds(fanout, &seed_sizes, &seed_sizes_count);
                setup_valid_internal_threads(fanout, internal_threads, &internal_threads_count);

                FOR_EVERY(size, seed_sizes, seed_sizes_count) {
                        // Setup seed
                        _log(LOG_INFO, "Testing seed size %zu B (%.2f MiB)\n", *size, MiB(*size));
                        SAFE_REALLOC(seed, *size);

                        // FOR_EVERY(config, ctxs, configs_count)
                        FOR_EVERY(ithr, internal_threads, internal_threads_count)
                        FOR_EVERY(ethr, external_threads, external_threads_count)
                        for (uint64_t exp = 1; exp <= MAX_EXPANSION; exp++) {
                                SAFE_REALLOC(out, exp * (*size));

                                ctx_keymix_init(&ctx, MIXCTRPASS_WOLFSSL, seed, *size, fanout);
                                test_keymix(&ctx, out, exp, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTRPASS_OPENSSL, seed, *size, fanout);
                                test_keymix(&ctx, out, exp, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTRPASS_AESNI, seed, *size, fanout);
                                test_keymix(&ctx, out, exp, *ithr, *ethr);
                        }
                }
        }

        fclose(fout);
        fout = NULL;
#endif

#ifdef DO_ENCRYPTION_TESTS
        fout = fopen(argv[2], "w");
        _log(LOG_INFO, "Testing encryption\n");

        csv_header();

        FOR_EVERY(fanout_p, fanouts, fanouts_count) {
                uint8_t fanout = *fanout_p;

                setup_seeds(fanout, &seed_sizes, &seed_sizes_count);
                setup_valid_internal_threads(fanout, internal_threads, &internal_threads_count);

                FOR_EVERY(size, seed_sizes, seed_sizes_count) {
                        // Setup seed
                        _log(LOG_INFO, "Testing seed size %zu B (%.2f MiB)\n", *size, MiB(*size));
                        SAFE_REALLOC(seed, *size);

                        FOR_EVERY(ithr, internal_threads, internal_threads_count)
                        FOR_EVERY(ethr, external_threads, external_threads_count)
                        for (uint64_t exp = 1; exp <= MAX_EXPANSION; exp++) {
                                SAFE_REALLOC(out, exp * (*size));
                                SAFE_REALLOC(in, exp * (*size));

                                ctx_keymix_init(&ctx, MIXCTRPASS_WOLFSSL, seed, *size, fanout);
                                test_enc(&ctx, in, out, exp, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTRPASS_OPENSSL, seed, *size, fanout);
                                test_enc(&ctx, in, out, exp, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTRPASS_AESNI, seed, *size, fanout);
                                test_enc(&ctx, in, out, exp, *ithr, *ethr);
                        }
                }
        }

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
