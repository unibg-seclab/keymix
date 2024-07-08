#include "keymix_t.h"

#include "keymix.h"
#include "utils.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

typedef struct {
        byte *seed;
        byte *out;
        size_t seed_size;
        size_t num_seeds;
        mixing_config *config;
        __uint128_t starting_iv;
} args_t;

void *w_keymix(void *a) {
        args_t *args = (args_t *)a;

        for (size_t i = 0; i < args->num_seeds; i++) {
                // TODO: apply IV
                keymix(args->seed, args->out, args->seed_size, args->config);

                args->seed += args->seed_size;
                args->out += args->seed_size;
                args->starting_iv++;
        }

        return NULL;
}

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             int num_threads) {
        pthread_t threads[num_threads];
        args_t args[num_threads];

        __uint128_t iv = 0;

        D assert(out_size % seed_size == 0 && "We can generate only multiples of seed_size");

        size_t remaining             = out_size / seed_size;
        size_t offset                = 0;
        unsigned int started_threads = 0;

        for (int t = 0; t < num_threads; t++) {
                if (remaining == 0) {
                        break;
                }

                size_t thread_seeds = MAX(1UL, remaining / (num_threads - t));
                remaining -= thread_seeds;

                args_t *a      = &args[t];
                a->seed        = seed;
                a->out         = out;
                a->num_seeds   = thread_seeds;
                a->seed_size   = seed_size;
                a->config      = config;
                a->starting_iv = iv;

                pthread_create(threads + t, NULL, w_keymix, a);
                started_threads++;

                seed += thread_seeds * seed_size;
                out += thread_seeds * seed_size;
                iv += thread_seeds;
        }
        D printf("Started %d threads\n", started_threads);

        assert(remaining == 0);

        for (int t = 0; t < started_threads; t++) {
                pthread_join(threads[t], NULL);
        }

        return 0;
}
