#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "enc.h"
#include "log.h"
#include "types.h"
#include "utils.h"

// -------------------------------------------------- Configure tests

#define SIZE_1KiB 1024UL
#define SIZE_1MiB (1024 * SIZE_1KiB)
#define SIZE_1GiB (1024 * SIZE_1MiB)

#define NUM_OF_TESTS 5
#define MIN_KEY_SIZE (8 * SIZE_1MiB)
#define MAX_KEY_SIZE (1.9 * SIZE_1GiB)

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
        fprintf(fout, "key_size,"); // Key size in B
        fprintf(fout, "outsize,");  // Output size, you can get expansion by dividing by key_size
        fprintf(fout,
                "internal_threads,");       // Number of internal threads
        fprintf(fout, "external_threads,"); // Number of threads to generate the different Ts
        fprintf(fout, "implementation,");   // AES implementation/library used
        fprintf(fout, "fanout,");           // Fanout
        fprintf(fout, "time\n");            // Time in ms
        fflush(fout);
}
void csv_line(size_t key_size, size_t size, uint8_t internal_threads, uint8_t external_threads,
              char *implementation, uint8_t fanout, double time) {
        fprintf(fout, "%zu,", key_size);
        fprintf(fout, "%zu,", size);
        fprintf(fout, "%d,", internal_threads);
        fprintf(fout, "%d,", external_threads);
        fprintf(fout, "%s,", implementation);
        fprintf(fout, "%d,", fanout);
        fprintf(fout, "%.2f\n", time);
        fflush(fout);
}

uint8_t first_x_that_surpasses(double bar, uint8_t fanout) {
        uint8_t x = 0;
        size_t size;
        do {
                x++;
                size = SIZE_MACRO * pow(fanout, x);
        } while (size < bar);

        return x;
}

void setup_keys(uint8_t fanout, size_t **key_sizes, uint8_t *key_sizes_count) {
        uint8_t min_x = first_x_that_surpasses(MIN_KEY_SIZE, fanout);
        uint8_t max_x = first_x_that_surpasses(MAX_KEY_SIZE, fanout);

        *key_sizes_count = max_x + 1 - min_x;
        *key_sizes       = realloc(*key_sizes, *key_sizes_count * sizeof(size_t));

        for (uint8_t x = min_x; x <= max_x; x++) {
                (*key_sizes)[x - min_x] = SIZE_MACRO * pow(fanout, x);
        }
}

void setup_valid_internal_threads(uint8_t fanout, uint8_t internal_threads[],
                                  uint8_t *internal_threads_count) {
        // Diff factors can be only one of 3, so we can just wing a switch
        // Just be sure to keep the maximum reasonable

        switch (fanout) {
        case 2:
                *internal_threads_count = 4;
                internal_threads[0]     = 1;
                internal_threads[1]     = 2;
                internal_threads[2]     = 4;
                internal_threads[3]     = 8;
                break;
        case 3:
                *internal_threads_count = 3;
                internal_threads[0]     = 1;
                internal_threads[1]     = 3;
                internal_threads[2]     = 9;
                break;
        case 4:
                *internal_threads_count = 2;
                internal_threads[0]     = 1;
                internal_threads[1]     = 4;
                break;
        }
}

// -------------------------------------------------- Actual test functions

void test_keymix(keymix_ctx_t *ctx, byte *out, size_t size, uint8_t internal_threads,
                 uint8_t external_threads) {
        char *impl = "(unspecified)";
        switch (ctx->mixctr) {
        case MIXCTR_AESNI:
                impl = "aesni";
                break;
        case MIXCTR_WOLFSSL:
                impl = "wolfssl";
                break;
        case MIXCTR_OPENSSL:
                impl = "openssl";
                break;
        }
        _log(LOG_INFO, "[TEST (i=%d, e=%d)] %s, fanout %d, expansion %zu: ", internal_threads,
             external_threads, impl, ctx->fanout, size / ctx->key_size);

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(keymix_t(ctx, out, size, external_threads, internal_threads));
                csv_line(ctx->key_size, size, internal_threads, external_threads, impl, ctx->fanout,
                         time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void test_enc(keymix_ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t internal_threads,
              uint8_t external_threads) {
        char *impl = "(unspecified)";
        switch (ctx->mixctr) {
        case MIXCTR_AESNI:
                impl = "aesni";
                break;
        case MIXCTR_WOLFSSL:
                impl = "wolfssl";
                break;
        case MIXCTR_OPENSSL:
                impl = "openssl";
                break;
        }
        _log(LOG_INFO, "[TEST (i=%d, e=%d)] %s, fanout %d, expansion %zu: ", internal_threads,
             external_threads, impl, ctx->fanout, CEILDIV(size, ctx->key_size));

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time =
                    MEASURE(encrypt_t(ctx, in, out, size, external_threads, internal_threads));
                csv_line(ctx->key_size, size, internal_threads, external_threads, impl, ctx->fanout,
                         time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

// -------------------------------------------------- Main loops

int main(int argc, char *argv[]) {
        if (argc < 3) {
#ifdef DO_KEYMIX_TESTS
                _log(LOG_INFO, "Doing keymix\n");
#endif
#ifdef DO_ENCRYPTION_TESTS
                _log(LOG_INFO, "Doing encryption\n");
#endif
                _log(LOG_INFO, "Usage:\n");
                _log(LOG_INFO, "  test [KEYMIX  OUTPUT] [ENCRIPTION SAME FILE OUTPUT]\n");
                return 1;
        }
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // Gli unici per cui il nostro schema funzione e ha senso
        uint8_t fanouts[]     = {2, 3, 4};
        uint8_t fanouts_count = sizeof(fanouts) / sizeof(__typeof__(*fanouts));

        byte *key = NULL;
        byte *out = NULL;
        byte *in  = NULL;

        size_t *key_sizes = NULL;
        uint8_t key_sizes_count;

        uint8_t external_threads[] = {1, 2, 4, 8};
        uint8_t external_threads_count =
            sizeof(external_threads) / sizeof(__typeof__(*external_threads));

        // There are never no more than 5 internal threads' values
        uint8_t internal_threads[5] = {0, 0, 0, 0, 0};
        uint8_t internal_threads_count;

        keymix_ctx_t ctx;

#ifdef DO_KEYMIX_TESTS
        fout = fopen(argv[1], "w");
        _log(LOG_INFO, "Testing keymix\n");

        csv_header();

        FOR_EVERY(fanout_p, fanouts, fanouts_count) {
                uint8_t fanout = *fanout_p;

                setup_keys(fanout, &key_sizes, &key_sizes_count);
                setup_valid_internal_threads(fanout, internal_threads, &internal_threads_count);

                FOR_EVERY(key_size_p, key_sizes, key_sizes_count) {
                        size_t key_size = *key_size_p;
                        _log(LOG_INFO, "Testing key size %zu B (%.2f MiB)\n", *key_size_p,
                             MiB(*key_size_p));
                        key = malloc(key_size);

                        FOR_EVERY(ithr, internal_threads, internal_threads_count)
                        FOR_EVERY(ethr, external_threads, external_threads_count) {
                                size_t size = key_size;

                                out = malloc(size);

                                ctx_keymix_init(&ctx, MIXCTR_WOLFSSL, key, key_size, fanout);
                                test_keymix(&ctx, out, size, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTR_OPENSSL, key, key_size, fanout);
                                test_keymix(&ctx, out, size, *ithr, *ethr);

                                ctx_keymix_init(&ctx, MIXCTR_AESNI, key, key_size, fanout);
                                test_keymix(&ctx, out, size, *ithr, *ethr);

                                free(out);
                        }

                        free(key);
                }
        }

        fclose(fout);
        fout = NULL;
#endif

#ifdef DO_ENCRYPTION_TESTS
        fout = fopen(argv[1], "w");
        _log(LOG_INFO, "Testing encryption\n");

        size_t file_sizes[]     = {SIZE_1MiB,       5 * SIZE_1MiB, 10 * SIZE_1MiB, 50 * SIZE_1MiB,
                                   100 * SIZE_1MiB, SIZE_1GiB,     5UL * SIZE_1GiB};
        size_t file_sizes_count = sizeof(file_sizes) / sizeof(size_t);

        csv_header();

        FOR_EVERY(fanout_p, fanouts, fanouts_count) {
                uint8_t fanout = *fanout_p;

                setup_keys(fanout, &key_sizes, &key_sizes_count);
                setup_valid_internal_threads(fanout, internal_threads, &internal_threads_count);

                FOR_EVERY(key_size_p, key_sizes, key_sizes_count) {
                        size_t key_size = *key_size_p;
                        _log(LOG_INFO, "Testing key size %zu B (%.2f MiB)\n", key_size,
                             MiB(key_size));
                        // SAFE_REALLOC(key, key_size);
                        key = malloc(key_size);

                        FOR_EVERY(ithr, internal_threads, internal_threads_count)
                        FOR_EVERY(ethr, external_threads, external_threads_count)
                        FOR_EVERY(sizep, file_sizes, file_sizes_count) {
                                size_t size = *sizep;

                                // SAFE_REALLOC(out, size);
                                // SAFE_REALLOC(in, size);
                                out = malloc(size);
                                in  = malloc(size);

                                ctx_encrypt_init(&ctx, MIXCTR_WOLFSSL, key, key_size, 0, fanout);
                                test_enc(&ctx, in, out, size, *ithr, *ethr);

                                ctx_encrypt_init(&ctx, MIXCTR_OPENSSL, key, key_size, 0, fanout);
                                test_enc(&ctx, in, out, size, *ithr, *ethr);

                                ctx_encrypt_init(&ctx, MIXCTR_AESNI, key, key_size, 0, fanout);
                                test_enc(&ctx, in, out, size, *ithr, *ethr);

                                free(out);
                                free(in);
                        }

                        free(key);
                }
        }

        fclose(fout);
        fout = NULL;
#endif

cleanup:
        if (fout)
                fclose(fout);
        free(key_sizes);
        return 0;
}
