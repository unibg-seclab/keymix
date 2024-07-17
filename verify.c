#include "aesni.h"
#include "config.h"
#include "keymix.h"
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
                        printf(__VA_ARGS__);                                                       \
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
        nof_threads = nof_threads == 0
                          ? pow(fanout, fmin(level, 3))
                          : nof_threads; // keep #threads under control w/o loss of generality

        if (nof_threads > (size / SIZE_MACRO))
                nof_threads = fanout;

        int thread_levels = level - fmin(level, 3); // only accurate when the nof_threads input to
                                                    // the function is 0

        pthread_t threads[nof_threads];
        run_thr_t thread_args[nof_threads];

        size_t thread_chunk_size = size / nof_threads;

        assert(size % nof_threads == 0);
        assert(thread_chunk_size % SIZE_MACRO == 0);

        for (int t = 0; t < nof_threads; t++) {
                run_thr_t *arg = thread_args + t;

                thread_data thr_data = {
                    .thread_id         = t,
                    .out               = in + t * thread_chunk_size,
                    .swp               = out + t * thread_chunk_size,
                    .abs_out           = in,
                    .abs_swp           = out,
                    .seed_size         = size,
                    .thread_chunk_size = thread_chunk_size,
                    .diff_factor       = fanout,
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

int verify_shuffles(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        printf("> Verifying swaps and shuffles AT level %zu (%.2f MiB)\n", level, MiB(size));

        byte *in       = setup(size, 1);
        byte *out_swap = setup(size, 0);
        // byte *out_swap2 = setup(out_swap2, size, 0);
        byte *out_shuffle  = setup(size, 0);
        byte *out_shuffle2 = setup(size, 0);
        byte *out_shuffle3 = setup(size, 0);
        byte *out_shuffle4 = setup(size, 0);
        byte *out_spread   = setup(size, 0);
        byte *out_spread2  = setup(size, 0);

        swap(out_swap, in, size, level, fanout);
        // emulate_shuffle_chunks(swap_chunks, out_swap2, in, size, level, fanout);
        shuffle(out_shuffle, in, size, level, fanout);
        shuffle_opt(out_shuffle2, in, size, level, fanout);
        emulate_shuffle_chunks(shuffle_chunks, out_shuffle3, in, size, level, fanout, 0);
        emulate_shuffle_chunks(shuffle_chunks_opt, out_shuffle4, in, size, level, fanout, 0);
        spread(out_spread, in, size, level, fanout);
        emulate_shuffle_chunks(spread_chunks, out_spread2, in, size, level, fanout, 0);

        int err = 0;
        err += COMPARE(out_swap, out_shuffle, size, "Swap != shuffle\n");
        // err += COMPARE(out_swap, out_swap2, size, "Swap != swap (chunks)\n");
        // err += COMPARE(out_shuffle, out_swap2, size, "Swap (chunks) != shuffle\n");
        err += COMPARE(out_shuffle, out_shuffle2, size, "Shuffle != shuffle (opt)\n");
        err += COMPARE(out_shuffle2, out_shuffle3, size, "Shuffle (opt) != shuffle (chunks)\n");
        err += COMPARE(out_shuffle3, out_swap, size, "Shuffle (chunks) != swap\n");
        err += COMPARE(out_shuffle3, out_shuffle, size, "Shuffle (chunks) != shuffle\n");
        err += COMPARE(out_shuffle3, out_shuffle4, size,
                       "Shuffle (chunks) != shuffle (chunks, opt)\n");

        err += COMPARE(out_spread, out_spread2, size, "Spread != spread (chunks)\n");

        free(in);
        free(out_swap);
        // free(out_swap2);
        free(out_shuffle);
        free(out_shuffle2);
        free(out_shuffle3);
        free(out_shuffle4);
        free(out_spread);
        free(out_spread2);

        return err;
}

int verify_multithreaded_shuffle(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        printf("> Verifying that shuffles AT level %zu are thread-independent (%.2f MiB)\n", level,
               MiB(size));

        byte *in = setup(size, 1);

        byte *out1 = setup(size, 0);
        byte *out2 = setup(size, 0);
        byte *out3 = setup(size, 0);

        byte *out4 = setup(size, 0);
        byte *out5 = setup(size, 0);
        byte *out6 = setup(size, 0);

        // Note, if fanout^2 is too high a number of threads, i.e., each thread
        // would get less than 1 macro, then the number of threads is brought
        // down to fanout
        emulate_shuffle_chunks(shuffle_chunks, out1, in, size, level, fanout, 1);
        emulate_shuffle_chunks(shuffle_chunks, out2, in, size, level, fanout, fanout);
        emulate_shuffle_chunks(shuffle_chunks, out3, in, size, level, fanout, fanout * fanout);

        emulate_shuffle_chunks(shuffle_chunks_opt, out4, in, size, level, fanout, 1);
        emulate_shuffle_chunks(shuffle_chunks_opt, out5, in, size, level, fanout, fanout);
        emulate_shuffle_chunks(shuffle_chunks_opt, out6, in, size, level, fanout, fanout * fanout);

        int err = 0;
        err += COMPARE(out1, out2, size, "1 thr != %zu thr\n", fanout);
        err += COMPARE(out2, out3, size, "%zu thr != %zu thr\n", fanout, fanout * fanout);
        err += COMPARE(out1, out3, size, "1 thr != %zu thr\n", fanout * fanout);

        err += COMPARE(out4, out5, size, "1 thr != %zu thr (opt)\n", fanout);
        err += COMPARE(out5, out6, size, "%zu thr != %zu thr (opt)\n", fanout, fanout * fanout);
        err += COMPARE(out4, out6, size, "1 thr != %zu thr (opt)\n", fanout * fanout);

        free(in);
        free(out1);
        free(out2);
        free(out3);
        free(out4);
        free(out5);
        free(out6);

        return err;
}

int verify_encs(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        printf("> Verifying encryption for size %.2f MiB\n", MiB(size));

        byte *in          = setup(size, 1);
        byte *out_wolfssl = setup(size, 0);
        byte *out_openssl = setup(size, 0);
        byte *out_aesni   = setup(size, 0);

        mixing_config config = {NULL, "", fanout};

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

int verify_multithreaded_encs(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        printf("> Verifying encryption for size %.2f MiB\n", MiB(size));

        byte *in         = setup(size, 1);
        byte *out_simple = setup(size, 0);
        byte *out1       = setup(size, 0);
        byte *out2       = setup(size, 0);
        byte *out3       = setup(size, 0);

        mixing_config config = {&aesni, "", fanout};

        // 1 thread
        keymix(in, out_simple, size, &config);
        parallel_keymix(in, out1, size, &config, 1);

        // Comparisons
        int err = 0;
        err += COMPARE(out_simple, out1, size, "Keymix != p-Keymix (1)\n");

        free(in);
        free(out_simple);
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
        unsigned int seed = time(NULL);
        srand(seed);

        int err = 0;

        for (size_t fanout = 2; fanout <= 4; fanout++) {
                printf("Verifying with fanout %zu\n", fanout);
                for (size_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        CHECKED(verify_shuffles(fanout, l));
                        CHECKED(verify_multithreaded_shuffle(fanout, l));
                        CHECKED(verify_encs(fanout, l));
                        CHECKED(verify_multithreaded_encs(fanout, l));
                }
                printf("\n");
        }

cleanup:
        if (err)
                printf("Failed, seed was %u\n", seed);
        else
                printf("All ok\n");
        return err;
}

#undef CHECKED

// Use this to measure stuff, but try and leave verify.c to do only the
// verification

// double t;
// double size_mib = (double)size / 1024 / 1024;

// printf("-------- fanout %zu, size %.2f MiB (13th level)\n", fanout,
//        size_mib);
// t = MEASURE(swap(out_swap, in, size, l, fanout));
// printf("Swap             %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
// t = MEASURE(shuffle(out_shuffle, in, size, l, fanout));
// printf("Shuffle          %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
// t = MEASURE(shuffle_opt(out_shuffle_opt, in, size, l, fanout));
// printf("Shuffle (opt)    %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
