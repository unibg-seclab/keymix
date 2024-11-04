#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "enc.h"
#include "keymix.h"
#include "log.h"
#include "types.h"
#include "utils.h"

// -------------------------------------------------- Configure tests

#define SIZE_1KiB 1024UL
#define SIZE_1MiB (1024 * SIZE_1KiB)
#define SIZE_1GiB (1024 * SIZE_1MiB)

#define NUM_OF_TESTS 5
#define NUM_OF_FANOUTS 3
#define NUM_OF_FANOUTS_ENC 1

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
        fprintf(fout, "internal_threads,"); // Number of internal threads
        fprintf(fout, "external_threads,"); // Kept for compatibility
        fprintf(fout, "enc_mode,");         // Encryption mode (none, ctr, ofb)
        fprintf(fout, "implementation,");   // Mixing implementation
        fprintf(fout, "one_way_mix_type,"); // One-way mixing implementation
        fprintf(fout, "fanout,");           // Fanout
        fprintf(fout, "time\n");            // Time in ms
        fflush(fout);
}
void csv_line(size_t key_size, size_t size, uint8_t threads, enc_mode_t enc_mode,
              mix_impl_t implementation, mix_impl_t one_way_mix_type, uint8_t fanout, double time) {
        fprintf(fout, "%zu,", key_size);
        fprintf(fout, "%zu,", size);
        fprintf(fout, "%d,", threads);
        fprintf(fout, "%d,", 1); // kept for compatibility
        fprintf(fout, "%s,", (enc_mode != -1 ? get_enc_mode_name(enc_mode) : "none"));
        fprintf(fout, "%s,", get_mix_name(implementation));
        fprintf(fout, "%s,", get_mix_name(one_way_mix_type));
        fprintf(fout, "%d,", fanout);
        fprintf(fout, "%.2f\n", time);
        fflush(fout);
}

uint8_t first_x_that_surpasses(double bar, block_size_t block_size, uint8_t fanout) {
        uint8_t x = 0;
        size_t size;
        do {
                x++;
                size = block_size * pow(fanout, x);
        } while (size < bar);

        return x;
}

void setup_keys(block_size_t block_size, uint8_t fanout, size_t **key_sizes,
                uint8_t *key_sizes_count) {
        uint8_t min_x = first_x_that_surpasses(MIN_KEY_SIZE, block_size, fanout);
        uint8_t max_x = first_x_that_surpasses(MAX_KEY_SIZE, block_size, fanout);

        *key_sizes_count = max_x + 1 - min_x;
        *key_sizes       = malloc(*key_sizes_count * sizeof(size_t));

        for (uint8_t x = min_x; x <= max_x; x++) {
                (*key_sizes)[x - min_x] = block_size * pow(fanout, x);
        }
}

// -------------------------------------------------- Actual test functions

void test_keymix(ctx_t *ctx, byte *out, size_t size, uint8_t threads) {
        _log(LOG_INFO, "[TEST (i=%d)] %s, fanout %d, expansion %zu: ", threads,
             get_mix_name(ctx->mix), ctx->fanout, size / ctx->key_size);

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(keymix_t(ctx, out, size, threads));
                csv_line(ctx->key_size, size, threads, -1, ctx->mix, NONE, ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void test_enc(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv, uint8_t threads) {
        _log(LOG_INFO,
             "[TEST (i=%d)] mode %s, main impl %s, one-way impl %s, fanout %d, expansion %zu: ",
             threads, get_enc_mode_name(ctx->enc_mode), get_mix_name(ctx->mix),
             get_mix_name(ctx->one_way_mix), ctx->fanout, CEILDIV(size, ctx->key_size));

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE(encrypt_t(ctx, in, out, size, iv, threads));
                csv_line(ctx->key_size, size, threads, ctx->enc_mode, ctx->mix,
                         ctx->one_way_mix, ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void test_ctr_enc_stream(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
                         uint8_t threads) {
        _log(LOG_INFO,
             "[TEST (i=%d)] mode %s, main impl %s, one-way impl %s, fanout %d, expansion %zu: ",
             threads, get_enc_mode_name(ctx->enc_mode), get_mix_name(ctx->mix),
             get_mix_name(ctx->one_way_mix), ctx->fanout, CEILDIV(size, ctx->key_size));

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE({
                        byte *tmpiv = malloc(KEYMIX_IV_SIZE);
                        memcpy(tmpiv, iv, KEYMIX_IV_SIZE);
                        byte *counter = tmpiv + KEYMIX_NONCE_SIZE;
                        size_t remaining_size = size;

                        while (remaining_size > 0) {
                                size_t to_encrypt = MIN(remaining_size, ctx->key_size);
                                encrypt_t(ctx, in, out, to_encrypt, tmpiv, threads);

                                if (remaining_size >= to_encrypt)
                                        remaining_size -= to_encrypt;
                                // Don't need to forward in/out
                                ctr64_inc(counter);
                        }
                });
                csv_line(ctx->key_size, size, threads, ctx->enc_mode, ctx->mix, ctx->one_way_mix,
                         ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void test_ofb_enc_stream(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
                         uint8_t threads) {
        byte *curr_key;
        byte *next_key;
        byte *outbuffer;
        size_t remaining_size;
        uint64_t keys_to_do;
        uint64_t nof_macros;
        size_t remaining_one_way_size;
        
        _log(LOG_INFO,
             "[TEST (i=%d)] mode %s, main impl %s, one-way impl %s, fanout %d, expansion %zu: ",
             threads, get_enc_mode_name(ctx->enc_mode), get_mix_name(ctx->mix),
             get_mix_name(ctx->one_way_mix), ctx->fanout, CEILDIV(size, ctx->key_size));

        for (uint8_t test = 0; test < NUM_OF_TESTS; test++) {
                double time = MEASURE({
                        curr_key = ctx->key;
                        next_key = malloc(ctx->key_size);
                        outbuffer = malloc(ctx->key_size);

                        remaining_size = size;
                        keys_to_do = CEILDIV(size, ctx->key_size);
                        for (uint64_t i = 0; i < keys_to_do; i++) {
                                keymix_iv(ctx, curr_key, next_key, ctx->key_size, iv, threads);
                                nof_macros = CEILDIV(remaining_size, ctx->one_way_block_size);
                                remaining_one_way_size = ctx->one_way_block_size * nof_macros;
                                (*ctx->one_way_mixpass)(next_key, outbuffer,
                                                        MIN(remaining_one_way_size, ctx->key_size),
                                                        iv);
                                multi_threaded_memxor(out, outbuffer, in,
                                                      MIN(remaining_size, ctx->key_size), threads);
                                curr_key = next_key;
                                if (remaining_size >= ctx->key_size)
                                        remaining_size -= ctx->key_size;
                        }

                        free(next_key);
                        free(outbuffer);
                });
                csv_line(ctx->key_size, size, threads, ctx->enc_mode, ctx->mix, ctx->one_way_mix,
                         ctx->fanout, time);
                _log(LOG_INFO, ".");
        }
        _log(LOG_INFO, "\n");
}

void do_encryption_tests(enc_mode_t enc_mode, mix_impl_t mix_type, mix_impl_t one_way_mix_type) {
        int err;
        byte *key;
        byte *out;
        byte *in;
        ctx_t ctx;
        mix_func_t mixpass;
        block_size_t block_size;
        uint8_t fanouts_enc[NUM_OF_FANOUTS_ENC];
        uint8_t fanouts_count;
        size_t *key_sizes;
        uint8_t key_sizes_count;

        byte iv[KEYMIX_IV_SIZE];
        for (uint8_t i = 0; i < KEYMIX_IV_SIZE; i++) {
                iv[i] = 0;
        }

        uint8_t threads[]     = {4};
        uint8_t threads_count = 1;

        size_t file_sizes[]     = {SIZE_1MiB, 10 * SIZE_1MiB, 100 * SIZE_1MiB,
                                   SIZE_1GiB, 10 * SIZE_1GiB, 100 * SIZE_1GiB};
        size_t file_sizes_count = sizeof(file_sizes) / sizeof(size_t);

        fanouts_count = get_fanouts_from_mix_type(mix_type, NUM_OF_FANOUTS_ENC, fanouts_enc);

        err = get_mix_func(mix_type, &mixpass, &block_size);
        if (err) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        FOR_EVERY(fanout_p, fanouts_enc, fanouts_count) {
                uint8_t fanout = *fanout_p;
                setup_keys(block_size, fanout, &key_sizes, &key_sizes_count);

                FOR_EVERY(key_size_p, key_sizes, key_sizes_count) {
                        size_t key_size = *key_size_p;
                        _log(LOG_INFO, "Testing key size %zu B (%.2f MiB)\n", key_size,
                             MiB(key_size));
                        key = malloc(key_size);

                        FOR_EVERY(thr, threads, threads_count)
                        FOR_EVERY(sizep, file_sizes, file_sizes_count) {
                                size_t size = *sizep;

                                ctx_encrypt_init(&ctx, enc_mode, mix_type, one_way_mix_type, key,
                                                 key_size, fanout);
                                if (size < 100 * SIZE_1GiB) {
                                        out = malloc(size);
                                        in  = out;
                                        test_enc(&ctx, in, out, size, iv, *thr);
                                        free(out);
                                } else {
                                        out = malloc(key_size);
                                        in  = out;
                                        if (enc_mode != ENC_MODE_OFB) {
                                                test_ctr_enc_stream(&ctx, in, out, size, iv, *thr);
                                        } else {
                                                test_ofb_enc_stream(&ctx, in, out, size, iv, *thr);
                                        }
                                        free(out);
                                }
                                ctx_free(&ctx);
                        }

                        free(key);
                }

                free(key_sizes);
        }
}

// -------------------------------------------------- Main loops

int main(int argc, char *argv[]) {
#ifdef DO_KEYMIX_TESTS
        _log(LOG_INFO, "Doing keymix\n");
#endif
#ifdef DO_ENCRYPTION_TESTS
        _log(LOG_INFO, "Doing encryption\n");
#endif

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        char *out_keymix = "data/out.csv";
        char *out_enc    = "data/enc.csv";

        const mix_impl_t *mix_types = MIX_TYPES;
        uint8_t mix_types_count = sizeof(MIX_TYPES) / sizeof(mix_impl_t);

        uint8_t fanouts[NUM_OF_FANOUTS];
        uint8_t fanouts_count;

        byte *key = NULL;
        byte *out = NULL;
        byte *in  = NULL;

        size_t *key_sizes = NULL;
        uint8_t key_sizes_count;

        uint8_t threads[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        uint8_t threads_count = 12;

        ctx_t ctx;

#define DO_KEYMIX_TESTS 1
#define DO_ENCRYPTION_TESTS 1

#ifdef DO_KEYMIX_TESTS
        fout = fopen(out_keymix, "w");
        _log(LOG_INFO, "Testing keymix\n");

        csv_header();

        FOR_EVERY(mix_type_p, mix_types, mix_types_count) {
                mix_impl_t mix_type = *mix_type_p;
                mix_func_t mix;
                block_size_t block_size;

                if (get_mix_func(mix_type, &mix, &block_size)) {
                        _log(LOG_ERROR, "Unknown mixing implementation\n");
                }

                fanouts_count = get_fanouts_from_block_size(block_size, NUM_OF_FANOUTS, fanouts);
                FOR_EVERY(fanout_p, fanouts, fanouts_count) {
                        uint8_t fanout = *fanout_p;
                        setup_keys(block_size, fanout, &key_sizes, &key_sizes_count);

                        FOR_EVERY(key_size_p, key_sizes, key_sizes_count) {
                                size_t key_size = *key_size_p;
                                _log(LOG_INFO, "Testing key size %zu B (%.2f MiB)\n", *key_size_p,
                                MiB(*key_size_p));
                                key = malloc(key_size);

                                FOR_EVERY(thr, threads, threads_count) {
                                        size_t size = key_size;

                                        out = malloc(size);

                                        ctx_keymix_init(&ctx, mix_type, key, key_size, fanout);
                                        test_keymix(&ctx, out, size, *thr);
                                        ctx_free(&ctx);

                                        free(out);
                                }

                                free(key);
                        }

                        free(key_sizes);
                }
        }

        fclose(fout);
        fout = NULL;
#endif

#ifdef DO_ENCRYPTION_TESTS
        fout = fopen(out_enc, "w");
        _log(LOG_INFO, "Testing encryption\n");

        csv_header();

        do_encryption_tests(ENC_MODE_CTR, XKCP_TURBOSHAKE_128, NONE);
        do_encryption_tests(ENC_MODE_CTR, OPENSSL_MATYAS_MEYER_OSEAS_128, NONE);
        do_encryption_tests(ENC_MODE_CTR, OPENSSL_AES_128, OPENSSL_MATYAS_MEYER_OSEAS_128);
        do_encryption_tests(ENC_MODE_CTR_OPT, XKCP_TURBOSHAKE_128, NONE);
        do_encryption_tests(ENC_MODE_CTR_OPT, OPENSSL_MATYAS_MEYER_OSEAS_128, NONE);
        do_encryption_tests(ENC_MODE_CTR_OPT, OPENSSL_AES_128, OPENSSL_MATYAS_MEYER_OSEAS_128);
        do_encryption_tests(ENC_MODE_OFB, OPENSSL_AES_128, OPENSSL_MATYAS_MEYER_OSEAS_128);

        fclose(fout);
        fout = NULL;
#endif

cleanup:
        if (fout)
                fclose(fout);
        free(key_sizes);
        return 0;
}
