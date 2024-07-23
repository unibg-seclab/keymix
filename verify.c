#include "aesni.h"
#include "config.h"
#include "keymix.h"
#include "keymix_t.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define MIN_LEVEL 1
#define MAX_LEVEL 12

#define COMPARE(a, b, size, ...)                                                                   \
        ({                                                                                         \
                int _err = 0;                                                                      \
                if (memcmp(a, b, size)) {                                                          \
                        _log(LOG_INFO, __VA_ARGS__);                                               \
                        _err = 1;                                                                  \
                }                                                                                  \
                _err;                                                                              \
        })

byte *setup(size_t size, int random) {
        byte *data = (byte *)malloc(size);
        for (size_t i = 0; i < size; i++) {
                data[i] = random ? (rand() % 256) : 0;
        }
        return data;
}

typedef struct {
        void (*func)(thread_data *, int);
        thread_data thr_data;
        int level;
} run_thr_t;

void *_run_thr(void *a) {
        run_thr_t *arg = (run_thr_t *)a;
        (*(arg->func))(&(arg->thr_data), arg->level);
        return NULL;
}

void emulate_shuffle_chunks(void (*func)(thread_data *, int), byte *out, byte *in, size_t size,
                            size_t level, size_t fanout, int nof_threads) {
        if (nof_threads > (size / SIZE_MACRO))
                nof_threads = fanout;

        int thread_levels = level - LOGBASE(nof_threads, fanout); // only accurate when the
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

        for (int t = 0; t < nof_threads; t++) {
                run_thr_t *arg = thread_args + t;

                thread_data thr_data = {
                    .thread_id         = t,
                    .out               = in + t * thread_chunk_size,
                    .buf               = out + t * thread_chunk_size,
                    .abs_out           = in,
                    .abs_buf           = out,
                    .seed_size         = size,
                    .thread_chunk_size = thread_chunk_size,
                    .mixconfig         = &mconf,
                    .thread_levels     = 1 + thread_levels,
                    .total_levels      = 1 + level,
                };

                arg->func     = func;
                arg->thr_data = thr_data;
                arg->level    = level;

                pthread_create(&threads[t], NULL, _run_thr, arg);
        }

        for (int t = 0; t < nof_threads; t++) {
                pthread_join(threads[t], NULL);
        }
}

// Verify equivalence of the shuffling operations for mixing a seed of size
// fanout^level macro blocks.
// Note, since shuffle and spread use two different mixing schemas these do
// not produce the same results, hence we do not compare them.
int verify_shuffles(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying swaps and shuffles up to level %zu (%.2f MiB)\n", level,
             MiB(size));

        byte *in       = setup(size, 1);
        byte *out_shuffle        = setup(size, 0);
        byte *out_shuffle2       = setup(size, 0);
        byte *out_shuffle3       = setup(size, 0);
        byte *out_shuffle4       = setup(size, 0);
        byte *out_spread         = setup(size, 0);
        byte *out_spread_inplace = setup(size, 0);
        byte *out_spread2        = setup(size, 0);

        int err = 0;
        for (int l = 1; l <= level; l++) {
                int nof_threads = pow(fanout, fmin(l, 3));
                bool is_shuffle_chunks_level = (level - l < fmin(l, 3));

                shuffle(out_shuffle, in, size, l, fanout);
                shuffle_opt(out_shuffle2, in, size, l, fanout);
                spread(out_spread, in, size, l, fanout);
                memcpy(out_spread_inplace, in, size);
                spread_inplace(out_spread_inplace, size, l, fanout);

                if (is_shuffle_chunks_level) {
                        emulate_shuffle_chunks(shuffle_chunks, out_shuffle3, in, size, l, fanout,
                                               nof_threads);
                        emulate_shuffle_chunks(shuffle_chunks_opt, out_shuffle4, in, size, l,
                                               fanout, nof_threads);
                        emulate_shuffle_chunks(spread_chunks, out_spread2, in, size, l, fanout,
                                               nof_threads);
                }

                // Note shuffle chunks opt is not working properly
                err += COMPARE(out_shuffle, out_shuffle2, size, "Shuffle != shuffle (opt)\n");
                if (is_shuffle_chunks_level) {
                        err += COMPARE(out_shuffle2, out_shuffle3, size,
                                       "Shuffle (opt) != shuffle (chunks)\n");
                        err += COMPARE(out_shuffle3, out_shuffle4, size,
                                       "Shuffle (chunks) != shuffle (chunks, opt)\n");
                        err += COMPARE(out_shuffle4, out_shuffle, size,
                                       "Shuffle (chunks, opt) != shuffle\n");
                }

                err += COMPARE(out_spread, out_spread_inplace, size,
                               "Spread != spread (inplace)\n");
                if (is_shuffle_chunks_level) {
                        err += COMPARE(out_spread_inplace, out_spread2, size,
                                       "Spread (inplace) != spread (chunks)\n");
                        err += COMPARE(out_spread2, out_spread, size,
                                       "Spread (chunks) != spread\n");
                }

                if (err) {
                        printf("Error at level %d/%ld (with %d threads)", l, level, nof_threads);
                        break;
                }
        }

        free(in);
        free(out_shuffle);
        free(out_shuffle2);
        free(out_shuffle3);
        free(out_shuffle4);
        free(out_spread);
        free(out_spread_inplace);
        free(out_spread2);

        return err;
}

int verify_multithreaded_shuffle(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying that shuffles AT level %zu are thread-independent (%.2f MiB)\n",
             level, MiB(size));

        byte *in = setup(size, 1);

        byte *out1 = setup(size, 0);
        byte *out2 = setup(size, 0);
        byte *out3 = setup(size, 0);

        byte *out4 = setup(size, 0);
        byte *out5 = setup(size, 0);
        byte *out6 = setup(size, 0);

        byte *out7 = setup(size, 0);
        byte *out8 = setup(size, 0);
        byte *out9 = setup(size, 0);

        // Note, if fanout^2 is too high a number of threads, i.e., each thread
        // would get less than 1 macro, then the number of threads is brought
        // down to fanout
        emulate_shuffle_chunks(shuffle_chunks, out1, in, size, level, fanout, 1);
        emulate_shuffle_chunks(shuffle_chunks, out2, in, size, level, fanout, fanout);
        emulate_shuffle_chunks(shuffle_chunks, out3, in, size, level, fanout, fanout * fanout);

        emulate_shuffle_chunks(shuffle_chunks_opt, out4, in, size, level, fanout, 1);
        emulate_shuffle_chunks(shuffle_chunks_opt, out5, in, size, level, fanout, fanout);
        emulate_shuffle_chunks(shuffle_chunks_opt, out6, in, size, level, fanout, fanout * fanout);

        spread(out7, in, size, level, fanout);

        // Note, we are not testing spread_chunks with one thread because it is meant to be used
        // only with multiple threads
        emulate_shuffle_chunks(spread_chunks, out8, in, size, level, fanout, fanout);
        emulate_shuffle_chunks(spread_chunks, out9, in, size, level, fanout, fanout * fanout);

        int err = 0;
        err += COMPARE(out1, out2, size, "1 thr != %zu thr\n", fanout);
        err += COMPARE(out2, out3, size, "%zu thr != %zu thr\n", fanout, fanout * fanout);
        err += COMPARE(out1, out3, size, "1 thr != %zu thr\n", fanout * fanout);

        err += COMPARE(out4, out5, size, "1 thr != %zu thr (opt)\n", fanout);
        err += COMPARE(out5, out6, size, "%zu thr != %zu thr (opt)\n", fanout, fanout * fanout);
        err += COMPARE(out4, out6, size, "1 thr != %zu thr (opt)\n", fanout * fanout);

        err += COMPARE(out7, out8, size, "1 thr (spread) != %zu thr (spread chunks)\n", fanout);
        err += COMPARE(out8, out9, size, "%zu thr (spread chunks) != %zu thr (spread chunks)\n",
                       fanout, fanout * fanout);
        err += COMPARE(out9, out7, size, "1 thr (spread) != %zu thr (spread chunks)\n",
                       fanout * fanout);

        free(in);
        free(out1);
        free(out2);
        free(out3);
        free(out4);
        free(out5);
        free(out6);
        free(out7);
        free(out8);
        free(out9);

        return err;
}

int verify_encs(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying encryption for size %.2f MiB\n", MiB(size));

        byte *in          = setup(size, 1);
        byte *out_wolfssl = setup(size, 0);
        byte *out_openssl = setup(size, 0);
        byte *out_aesni   = setup(size, 0);

        mixing_config config = {NULL, fanout};

        config.mixfunc = &wolfssl;
        keymix(in, out_wolfssl, size, &config);

        config.mixfunc = &openssl;
        keymix(in, out_openssl, size, &config);

        config.mixfunc = &aesni;
        keymix(in, out_aesni, size, &config);

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

int verify_multithreaded_encs(size_t fanout, size_t level, bool inplace) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying parallel-keymix equivalence for size %.2f MiB\n", MiB(size));

        byte *in         = setup(size, 1);
        byte *out_simple = setup(size, 0);
        byte *out1       = setup(size, 0);
        byte *outf       = setup(size, 0);
        byte *outff      = setup(size, 0);
        byte *outfff     = setup(size, 0);

        size_t thr1   = 1;
        size_t thrf   = fanout;
        size_t thrff  = fanout * fanout;
        size_t thrfff = fanout * fanout * fanout;

        mixing_config config = {&aesni, fanout, inplace};

        keymix(in, out_simple, size, &config);
        parallel_keymix(in, out1, size, &config, thr1);
        parallel_keymix(in, outf, size, &config, thrf);
        parallel_keymix(in, outff, size, &config, thrff);
        parallel_keymix(in, outfff, size, &config, thrfff);

        // Comparisons
        int err = 0;
        err += COMPARE(out_simple, out1, size, "Keymix != p-Keymix (1)\n");

        err += COMPARE(out1, outf, size, "p-Keymix (1) != p-Keymix (%zu)\n", thrf);
        err += COMPARE(out_simple, outf, size, "Keymix != p-Keymix (%zu)\n", thrf);

        err += COMPARE(out_simple, outff, size, "Keymix != p-Keymix (%zu)\n", thrff);
        err += COMPARE(out1, outff, size, "p-Keymix (1) != p-Keymix (%zu)\n", thrff);
        err += COMPARE(outf, outff, size, "p-Keymix (%zu) != p-Keymix (%zu)\n", thrf, thrff);

        err += COMPARE(out_simple, outfff, size, "Keymix != p-Keymix (%zu)\n", thrfff);
        err += COMPARE(out1, outfff, size, "p-Keymix (1) != p-Keymix (%zu)\n", thrfff);
        err += COMPARE(outf, outfff, size, "p-Keymix (%zu) != p-Keymix (%zu)\n", thrf, thrfff);
        err += COMPARE(outff, outfff, size, "p-Keymix (%zu) != p-Keymix (%zu)\n", thrff, thrff);

        free(in);
        free(out_simple);
        free(out1);
        free(outf);
        free(outff);
        free(outfff);

        return err;
}

int verify_keymix_t(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        _log(LOG_INFO, "> Verifying keymix-t equivalence for size %.2f MiB\n", MiB(size));

        byte *in         = setup(size, 1);
        byte *in_simple  = setup(size, 0);
        byte *out_simple = setup(size, 0);
        byte *out1       = setup(size, 0);
        byte *out2_thr1  = setup(2 * size, 0);
        byte *out2_thr2  = setup(2 * size, 0);
        byte *out3_thr1  = setup(3 * size, 0);
        byte *out3_thr2  = setup(3 * size, 0);

        mixing_config conf = {&aesni, fanout};

        __uint128_t iv       = rand() % (1 << sizeof(__uint128_t));
        int internal_threads = 1;

        // Note: Keymix T applies the IV, so we have to do that manually
        // to the input of Keymix
        for (size_t i = 0; i < size; i++) {
                in_simple[i] = in[i];
        }
        *(__uint128_t *)in_simple ^= iv;
        keymix(in_simple, out_simple, size, &conf);
        keymix_t(in, size, out1, size, &conf, 1, internal_threads, iv);

        keymix_t(in, size, out2_thr1, 2 * size, &conf, 1, internal_threads, iv);
        keymix_t(in, size, out2_thr2, 2 * size, &conf, 2, internal_threads, iv);
        keymix_t(in, size, out3_thr1, 3 * size, &conf, 1, internal_threads, iv);
        keymix_t(in, size, out3_thr2, 3 * size, &conf, 2, internal_threads, iv);

        int err = 0;
        err += COMPARE(out_simple, out1, size, "Keymix T (x1, 1thr) != Keymix\n");
        err += COMPARE(out2_thr1, out2_thr2, size, "Keymix T (x2, 1thr) != Keymix T (x2, 2thr)\n");
        err += COMPARE(out3_thr1, out3_thr2, size, "Keymix T (x3, 1thr) != Keymix T (x3, 2thr)\n");

        free(in);
        free(out1);
        free(out2_thr1);
        free(out2_thr2);
        free(out3_thr1);
        free(out3_thr2);

        return err;
}

#define CHECKED(F)                                                                                 \
        err = F;                                                                                   \
        if (err)                                                                                   \
                goto cleanup;

int main() {
        unsigned int seed = time(NULL);
        srand(seed);

        int err = 0;

        for (size_t fanout = 2; fanout <= 4; fanout++) {
                _log(LOG_INFO, "Verifying with fanout %zu\n", fanout);
                for (size_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        CHECKED(verify_shuffles(fanout, l));
                        CHECKED(verify_multithreaded_shuffle(fanout, l));
                        CHECKED(verify_encs(fanout, l));
                        CHECKED(verify_multithreaded_encs(fanout, l, true));
                        CHECKED(verify_multithreaded_encs(fanout, l, false));
                        CHECKED(verify_keymix_t(fanout, l));
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
