#include "keymix_t.h"

#include "keymix.h"
#include "utils.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

typedef struct {
        byte *seed;
        byte *out;
        size_t seed_size;
        uint64_t num_seeds;
        mixing_config *config;
        uint128_t iv;
        uint128_t starting_counter;

        int internal_threads;
} args_t;

void *w_keymix(void *a) {
        args_t *args = (args_t *)a;

        uint128_t counter = args->starting_counter;

        // Keep a local copy of the seed: it needs to be modified, and we are
        // in a multithreaded environment, so we can't just overwrite the same
        // memory area while other threads are trying to read it and modify it
        // themselves
        byte *buffer = malloc(args->seed_size);
        memcpy(buffer, args->seed, args->seed_size);

        // The seed gets modified as follows
        // First block -> XOR with (unchanging) IV
        // Second block -> XOR with a counter

        uint128_t *buffer_as_blocks     = (uint128_t *)buffer;
        uint128_t second_block_original = buffer_as_blocks[1];

        buffer_as_blocks[0] ^= args->iv;

        for (uint64_t i = 0; i < args->num_seeds; i++) {
                buffer_as_blocks[1] = second_block_original ^ counter;
                keymix(buffer, args->out, args->seed_size, args->config, args->internal_threads);

                args->out += args->seed_size;
                counter++;
        }

        free(buffer);
        return NULL;
}

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             uint32_t num_threads, uint32_t internal_threads, uint128_t iv) {
        pthread_t threads[num_threads];
        args_t args[num_threads];

        if (num_threads == 1) {
                args_t a;
                a.seed             = seed;
                a.out              = out;
                a.num_seeds        = 1;
                a.seed_size        = seed_size;
                a.config           = config;
                a.iv               = iv;
                a.starting_counter = 0;
                a.internal_threads = internal_threads;
                w_keymix(&a);
                return 0;
        }

        uint128_t counter = 0;

        if (DEBUG)
                assert(out_size % seed_size == 0 && "We can generate only multiples of seed_size");

        uint64_t remaining       = out_size / seed_size;
        uint64_t offset          = 0;
        uint32_t started_threads = 0;

        for (int t = 0; t < num_threads; t++) {
                if (remaining == 0) {
                        break;
                }

                uint64_t thread_seeds = MAX(1UL, remaining / (num_threads - t));
                remaining -= thread_seeds;

                args_t *a           = &args[t];
                a->seed             = seed;
                a->out              = out;
                a->num_seeds        = thread_seeds;
                a->seed_size        = seed_size;
                a->config           = config;
                a->iv               = iv;
                a->starting_counter = counter;
                a->internal_threads = internal_threads;

                pthread_create(threads + t, NULL, w_keymix, a);
                started_threads++;

                out += thread_seeds * seed_size;
                counter += thread_seeds;
        }
        if (DEBUG)
                _log(LOG_DEBUG, "Started %d threads\n", started_threads);

        assert(remaining == 0);

        for (int t = 0; t < started_threads; t++) {
                pthread_join(threads[t], NULL);
        }

        return 0;
}
