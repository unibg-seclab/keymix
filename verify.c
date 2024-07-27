#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "enc.h"
#include "keymix.h"
#include "log.h"
#include "mixctr.h"
#include "spread.h"
#include "types.h"
#include "utils.h"

#define MIN_LEVEL 1
#define MAX_LEVEL 9

#define COMPARE(a, b, size, ...)                                                                   \
        ({                                                                                         \
                int _err = 0;                                                                      \
                if (memcmp(a, b, size)) {                                                          \
                        _log(LOG_INFO, __VA_ARGS__);                                               \
                        _err = 1;                                                                  \
                }                                                                                  \
                _err;                                                                              \
        })

byte *setup(size_t size, bool random) {
        byte *data = (byte *)malloc(size);
        for (size_t i = 0; i < size; i++) {
                data[i] = random ? (rand() % 256) : 0;
        }
        return data;
}

inline double MiB(size_t size) { return (double)size / 1024 / 1024; }

typedef struct {
        spread_chunks_args_t thr_data;
        uint8_t level;
} run_thr_t;

void *_run_thr(void *a) {
        run_thr_t *arg = (run_thr_t *)a;
        spread_chunks(&(arg->thr_data), arg->level);
        return NULL;
}

void emulate_spread_chunks(byte *buffer, size_t size, uint8_t level, uint8_t fanout,
                           uint8_t nof_threads) {
        if (nof_threads > (size / SIZE_MACRO))
                nof_threads = fanout;

        uint8_t thread_levels = level - LOGBASE(nof_threads, fanout); // only accurate when the
                                                                      // nof_threads is a power of
                                                                      // fanout

        pthread_t threads[nof_threads];
        run_thr_t thread_args[nof_threads];

        size_t thread_chunk_size = size / nof_threads;

        assert(size % nof_threads == 0);
        assert(thread_chunk_size % SIZE_MACRO == 0);

        // We are emulating only shuffling around, no need to set an encryption
        // function
        mixing_config mconf = {NULL, fanout};

        for (uint8_t t = 0; t < nof_threads; t++) {
                run_thr_t *arg = thread_args + t;

                // Note: this must remain not a pointer when passed into the
                // thread, because GCC allocates only 1 thr_data and changes it
                // instead of allocating 1 for every for.
                spread_chunks_args_t thr_data = {
                    .thread_id       = t,
                    .buffer          = buffer + t * thread_chunk_size,
                    .buffer_abs      = buffer,
                    .buffer_abs_size = size,
                    .buffer_size     = thread_chunk_size,
                    .fanout          = fanout,
                    .thread_levels   = 1 + thread_levels,
                    .total_levels    = 1 + level,
                };

                arg->thr_data = thr_data;
                arg->level    = level;

                pthread_create(&threads[t], NULL, _run_thr, arg);
        }

        for (uint8_t t = 0; t < nof_threads; t++) {
                pthread_join(threads[t], NULL);
        }
}

// Verify equivalence of the shuffling operations for mixing a seed of size
// fanout^level macro blocks.
// Note, since shuffle and spread use two different mixing schemas these do
// not produce the same results, hence we do not compare them.
int verify_shuffles(size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying swaps and shuffles up to level %zu (%.2f MiB)\n", level,
             MiB(size));

        byte *in                = setup(size, true);
        byte *out_spread        = setup(size, false);
        byte *out_spread_chunks = setup(size, false);

        int err = 0;
        for (uint8_t l = 1; l <= level; l++) {
                uint8_t nof_threads          = pow(fanout, fmin(l, 3));
                bool is_shuffle_chunks_level = (level - l < fmin(l, 3));

                // Fill in buffer of the inplace operations
                memcpy(out_spread, in, size);
                memcpy(out_spread_chunks, in, size);

                spread(out_spread, size, l, fanout);

                if (is_shuffle_chunks_level) {
                        emulate_spread_chunks(out_spread_chunks, size, l, fanout, nof_threads);

                        err += COMPARE(out_spread, out_spread_chunks, size,
                                       "Spread (inplace) != spread (chunks inplace)\n");
                }

                if (err) {
                        _log(LOG_INFO, "Error at level %d/%d (with %d threads)", l, level,
                             nof_threads);
                        break;
                }
        }

        free(in);
        free(out_spread);
        free(out_spread_chunks);

        return err;
}

// Verify equivalence of the shuffling operations for mixing a seed of size
// fanout^level macro blocks with a varying number of threads.
// Note, since shuffle and spread use two different mixing schemas these do
// not produce the same results, hence we do not compare them.
int verify_shuffles_with_varying_threads(size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying that shuffles AT level %zu are thread-independent (%.2f MiB)\n",
             level, MiB(size));

        byte *in = setup(size, true);

        byte *out1 = setup(size, false);
        byte *out2 = setup(size, false);
        byte *out3 = setup(size, false);

        // The following functions work inplace. So to avoid overwriting the input we copy it
        memcpy(out1, in, size);
        memcpy(out2, in, size);
        memcpy(out3, in, size);
        // Note, we are not testing spread_chunks with one thread because it is meant to be
        // used only with multiple threads
        spread(out1, size, level, fanout);
        emulate_spread_chunks(out2, size, level, fanout, fanout);
        emulate_spread_chunks(out3, size, level, fanout, fanout * fanout);

        int err = 0;

        err += COMPARE(out1, out2, size,
                       "1 thr (spread inplace) != %zu thr (spread chunks inplace)\n", fanout);
        err += COMPARE(out2, out3, size,
                       "%zu thr (spread chunks inplace) != %zu thr (spread chunks inplace)\n",
                       fanout, fanout * fanout);
        err +=
            COMPARE(out3, out1, size, "1 thr (spread inplace) != %zu thr (spread chunks inplace)\n",
                    fanout * fanout);

        free(in);
        free(out1);
        free(out2);
        free(out3);

        return err;
}

// Verify the equivalence of the results when using different encryption
// functions (i.e., AES-NI, OpenSSL, WolfSSL)
int verify_keymix(size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying keymix mixctr-independence for size %.2f MiB\n", MiB(size));

        byte *in          = setup(size, true);
        byte *out_wolfssl = setup(size, false);
        byte *out_openssl = setup(size, false);
        byte *out_aesni   = setup(size, false);

        keymix(&wolfssl, in, out_wolfssl, size, fanout, 1);
        keymix(&openssl, in, out_openssl, size, fanout, 1);
        keymix(&aesni, in, out_aesni, size, fanout, 1);

        int err = 0;
        err += COMPARE(out_wolfssl, out_openssl, size, "WolfSSL != OpenSSL\n");
        err += COMPARE(out_openssl, out_aesni, size, "OpenSSL != AES-NI (opt)\n");
        err += COMPARE(out_wolfssl, out_aesni, size, "WolfSSL != AES-NI (opt)\n");

        free(in);
        free(out_wolfssl);
        free(out_openssl);
        free(out_aesni);

        return err;
}

// Verify the equivalence of the results when using single-threaded and
// multi-threaded encryption with a varying number of threads
int verify_multithreaded_keymix(size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying keymix threading-independence for size %.2f MiB\n", MiB(size));

        byte *in     = setup(size, true);
        byte *out1   = setup(size, false);
        byte *outf   = setup(size, false);
        byte *outff  = setup(size, false);
        byte *outfff = setup(size, false);

        size_t thr1   = 1;
        size_t thrf   = fanout;
        size_t thrff  = fanout * fanout;
        size_t thrfff = fanout * fanout * fanout;

        keymix(&aesni, in, out1, size, fanout, thr1);
        keymix(&aesni, in, outf, size, fanout, thrf);
        keymix(&aesni, in, outff, size, fanout, thrff);
        keymix(&aesni, in, outfff, size, fanout, thrfff);

        // Comparisons
        int err = 0;
        err += COMPARE(out1, outf, size, "Keymix (1) != Keymix (%zu)\n", thrf);

        err += COMPARE(out1, outff, size, "Keymix (1) != Keymix (%zu)\n", thrff);
        err += COMPARE(outf, outff, size, "Keymix (%zu) != Keymix (%zu)\n", thrf, thrff);

        err += COMPARE(out1, outfff, size, "Keymix (1) != Keymix (%zu)\n", thrfff);
        err += COMPARE(outf, outfff, size, "Keymix (%zu) != Keymix (%zu)\n", thrf, thrfff);
        err += COMPARE(outff, outfff, size, "Keymix (%zu) != Keymix (%zu)\n", thrff, thrff);

        free(in);
        free(out1);
        free(outf);
        free(outff);
        free(outfff);

        return err;
}

int verify_keymix_t(size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying keymix-t equivalence for size %.2f MiB\n", MiB(size));

        byte *in         = setup(size, true);
        byte *out_simple = setup(size, false);
        byte *out1       = setup(size, false);
        byte *out2_thr1  = setup(2 * size, 0);
        byte *out2_thr2  = setup(2 * size, 0);
        byte *out3_thr1  = setup(3 * size, 0);
        byte *out3_thr2  = setup(3 * size, 0);

        uint128_t iv             = rand() % (1 << sizeof(uint128_t));
        uint8_t internal_threads = 1;

        keymix_ctx_t ctx;
        ctx_keymix_init(&ctx, MIXCTR_AESNI, in, size, fanout);

        keymix(&aesni, in, out_simple, size, fanout, 1);
        keymix_t(&ctx, out1, size, 1, internal_threads);

        keymix_t(&ctx, out2_thr1, 2 * size, 1, internal_threads);
        keymix_t(&ctx, out2_thr2, 2 * size, 2, internal_threads);
        keymix_t(&ctx, out3_thr1, 3 * size, 1, internal_threads);
        keymix_t(&ctx, out3_thr2, 3 * size, 2, internal_threads);

        int err = 0;
        err += COMPARE(out_simple, out1, size, "Keymix T (x1, 1thr) != Keymix\n");
        err += COMPARE(out2_thr1, out2_thr2, size, "Keymix T (x2, 1thr) != Keymix T (x2, 2thr)\n");
        err += COMPARE(out3_thr1, out3_thr2, size, "Keymix T (x3, 1thr) != Keymix T (x3, 2thr)\n");

        free(in);
        free(out_simple);
        free(out1);
        free(out2_thr1);
        free(out2_thr2);
        free(out3_thr1);
        free(out3_thr2);

        return err;
}

int verify_enc(size_t fanout, uint8_t level) {
        size_t key_size      = (size_t)pow(fanout, level) * SIZE_MACRO;
        size_t resource_size = (rand() % 5) * key_size + (rand() % key_size);

        _log(LOG_INFO, "> Verifying encryption for key size %.2f MiB\n", MiB(key_size));

        uint128_t iv = rand() % (1 << sizeof(uint128_t));

        int err   = 0;
        byte *key = setup(key_size, true);
        byte *in  = setup(resource_size, true);

        byte *out1 = setup(resource_size, false);
        byte *out2 = setup(resource_size, false);
        byte *out3 = setup(resource_size, false);

        keymix_ctx_t ctx;
        ctx_encrypt_init(&ctx, MIXCTR_AESNI, key, key_size, iv, fanout);

        encrypt(&ctx, in, out1, resource_size);
        encrypt_t(&ctx, in, out2, resource_size, 2, 1);
        encrypt_t(&ctx, in, out3, resource_size, 3, 1);

        err += COMPARE(out1, out2, resource_size, "Encrypt != Encrypt (2thr)\n");
        err += COMPARE(out1, out3, resource_size, "Encrypt != Encrypt (3thr)\n");
        err += COMPARE(out2, out3, resource_size, "Encrypt (2thr) != Encrypt (3thr)\n");

        encrypt_t(&ctx, in, out2, resource_size, 1, fanout);
        encrypt_t(&ctx, in, out3, resource_size, 1, fanout * fanout);
        err += COMPARE(out1, out2, resource_size, "Encrypt != Encrypt (%d int-thr)\n", fanout);
        err += COMPARE(out1, out3, resource_size, "Encrypt != Encrypt (%d int-thr)\n",
                       fanout * fanout);
        err += COMPARE(out2, out3, resource_size, "Encrypt (%d int-thr) != Encrypt (%d int-thr)\n",
                       fanout, fanout * fanout);

        free(key);
        free(out1);
        free(out2);
        free(out3);
        return err;
}

#define CHECKED(F)                                                                                 \
        err = F;                                                                                   \
        if (err)                                                                                   \
                goto cleanup;

int main() {
        uint64_t seed = time(NULL);
        srand(seed);

        int err = 0;

        for (uint8_t fanout = 2; fanout <= 4; fanout++) {
                _log(LOG_INFO, "Verifying with fanout %zu\n", fanout);
                for (uint8_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        CHECKED(verify_shuffles(fanout, l));
                        CHECKED(verify_shuffles_with_varying_threads(fanout, l));
                        CHECKED(verify_keymix(fanout, l));
                        CHECKED(verify_multithreaded_keymix(fanout, l));
                        CHECKED(verify_keymix_t(fanout, l));
                        CHECKED(verify_enc(fanout, l));
                }
                _log(LOG_INFO, "\n");
        }

cleanup:
        if (err)
                _log(LOG_INFO, "Failed, seed was %u\n", seed);
        else
                _log(LOG_INFO, "All ok\n");
        return err;
}

#undef CHECKED
