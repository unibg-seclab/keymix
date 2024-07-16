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

#define COMPARE(a, b, size, msg)                                                                   \
        ({                                                                                         \
                int _err = 0;                                                                      \
                if (memcmp(a, b, size)) {                                                          \
                        printf(msg);                                                               \
                        _err = 1;                                                                  \
                }                                                                                  \
                _err;                                                                              \
        })

void setup(byte *data, size_t size, int random) {
        for (size_t i = 0; i < size; i++) {
                data[i] = random ? (rand() % 256) : 0;
        }
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
                            size_t level, size_t fanout) {
        int nof_threads =
            pow(fanout, fmin(level, 3)); // keep #threads under control w/o loss of generality

        assert(size % nof_threads == 0);

        pthread_t threads[nof_threads];
        run_thr_t thread_args[nof_threads];

        size_t thread_chunk_size = size / nof_threads;
        int thread_levels        = level - fmin(level, 3);

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
                    .thread_levels     = thread_levels, // Not used
                    .total_levels      = level,         // Not used
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

        byte *in       = malloc(size);
        byte *out_swap = malloc(size);
        // byte *out_swap2    = malloc(size);
        byte *out_shuffle  = malloc(size);
        byte *out_shuffle2 = malloc(size);
        byte *out_shuffle3 = malloc(size);

        setup(in, size, 1);
        setup(out_swap, size, 0);
        // setup(out_swap2, size, 0);
        setup(out_shuffle, size, 0);
        setup(out_shuffle2, size, 0);
        setup(out_shuffle3, size, 0);

        swap(out_swap, in, size, level, fanout);
        // emulate_shuffle_chunks(swap_chunks, out_swap2, in, size, level, fanout);
        shuffle(out_shuffle, in, size, level, fanout);
        shuffle_opt(out_shuffle2, in, size, level, fanout);
        emulate_shuffle_chunks(shuffle_chunks, out_shuffle3, in, size, level, fanout);

        int err = 0;
        err += COMPARE(out_swap, out_shuffle, size, "Swap != shuffle\n");
        // err += COMPARE(out_swap, out_swap2, size, "Swap != swap (chunks)\n");
        // err += COMPARE(out_shuffle, out_swap2, size, "Swap (chunks) != shuffle\n");
        err += COMPARE(out_shuffle, out_shuffle2, size, "Shuffle != shuffle (opt)\n");
        err += COMPARE(out_shuffle2, out_shuffle3, size, "Shuffle (opt) != shuffle (chunks)\n");
        err += COMPARE(out_shuffle3, out_swap, size, "Shuffle (chunks) != swap\n");

        free(in);
        free(out_swap);
        // free(out_swap2);
        free(out_shuffle);
        free(out_shuffle2);
        free(out_shuffle3);

        return err;
}

int verify_encs(size_t fanout, size_t level) {
        size_t size = (size_t)pow(fanout, level) * SIZE_MACRO;

        printf("> Verifying encryption for size %.2f MiB\n", MiB(size));

        byte *in          = malloc(size);
        byte *out_wolfssl = malloc(size);
        byte *out_openssl = malloc(size);
        byte *out_aesni   = malloc(size);

        setup(in, size, 1);
        setup(out_wolfssl, size, 0);
        setup(out_openssl, size, 0);
        setup(out_aesni, size, 0);

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

int main() {
        unsigned int seed = time(NULL);
        srand(seed);

        int err = 0;

        for (size_t fanout = 2; fanout <= 4; fanout++) {
                printf("Verifying with fanout %zu\n", fanout);
                for (size_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        err = verify_shuffles(fanout, l);
                        if (err)
                                goto cleanup;

                        err = verify_encs(fanout, l);
                        if (err)
                                goto cleanup;
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
