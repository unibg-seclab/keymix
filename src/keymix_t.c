#include "keymix_t.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "keymix.h"
#include "log.h"
#include "utils.h"

typedef struct {
        byte *seed;
        byte *in;
        byte *out;
        size_t seed_size;
        size_t in_out_size;
        uint64_t num_seeds;
        mixing_config *config;
        uint128_t iv;
        uint128_t starting_counter;
        uint8_t internal_threads;
        bool encrypt;
} args_t;

void *w_keymix(void *a) {
        args_t *args = (args_t *)a;

        // Keep a local copy of the seed: it needs to be modified, and we are
        // in a multithreaded environment, so we can't just overwrite the same
        // memory area while other threads are trying to read it and modify it
        // themselves
        byte *buffer = malloc(args->seed_size);
        memcpy(buffer, args->seed, args->seed_size);

        // The seed gets modified as follows
        // First block -> XOR with (unchanging) IV
        // Second block -> incremented

        uint128_t *buffer_as_blocks = (uint128_t *)buffer;
        buffer_as_blocks[0] ^= args->iv;
        buffer_as_blocks[1] += args->starting_counter;

        for (uint64_t i = 0; i < args->num_seeds; i++) {
                keymix(buffer, args->out, args->seed_size, args->config, args->internal_threads);
                if (args->encrypt) {
                        memxor(args->out, args->in, MIN(args->in_out_size, args->seed_size));
                }

                args->out += args->seed_size;
                if (args->in_out_size >= args->seed_size)
                        args->in_out_size -= args->seed_size;
                buffer_as_blocks[1]++;
        }

        free(buffer);
        return NULL;
}

int keymix_ex(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
              uint8_t num_threads, uint8_t internal_threads, uint128_t iv, bool encrypt,
              uint128_t starting_counter) {
        pthread_t threads[num_threads];
        args_t args[num_threads];

        assert(size % seed_size == 0 && "We can generate only multiples of seed_size");

        uint64_t num_seeds = size / seed_size;
        uint128_t counter  = starting_counter;

        if (num_threads == 1) {
                args_t a;
                a.seed             = seed;
                a.in               = in;
                a.out              = out;
                a.num_seeds        = num_seeds;
                a.seed_size        = seed_size;
                a.in_out_size      = size;
                a.config           = config;
                a.iv               = iv;
                a.starting_counter = counter;
                a.internal_threads = internal_threads;
                a.encrypt          = encrypt;
                w_keymix(&a);
                return 0;
        }

        uint64_t offset         = 0;
        uint8_t started_threads = 0;

        for (uint8_t t = 0; t < num_threads; t++) {
                if (num_seeds == 0) {
                        break;
                }

                uint64_t thread_seeds = MAX(1UL, num_seeds / (num_threads - t));
                num_seeds -= thread_seeds;

                args_t *a           = &args[t];
                a->seed             = seed;
                a->in               = in;
                a->out              = out;
                a->num_seeds        = thread_seeds;
                a->seed_size        = seed_size;
                a->in_out_size      = size;
                a->config           = config;
                a->iv               = iv;
                a->starting_counter = counter;
                a->internal_threads = internal_threads;
                a->encrypt          = encrypt;

                pthread_create(threads + t, NULL, w_keymix, a);
                started_threads++;

                in += thread_seeds * seed_size;
                out += thread_seeds * seed_size;
                counter += thread_seeds;
        }
        _log(LOG_DEBUG, "Started %d threads\n", started_threads);

        assert(num_seeds == 0);

        for (uint8_t t = 0; t < started_threads; t++) {
                pthread_join(threads[t], NULL);
        }

        return 0;
}

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             uint8_t num_threads, uint8_t internal_threads, uint128_t iv) {
        return keymix_ex(seed, seed_size, NULL, out, out_size, config, num_threads,
                         internal_threads, iv, false, 0);
}

int enc(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
        uint8_t num_threads, uint128_t iv) {
        return enc_ex(seed, seed_size, in, out, size, config, num_threads, 1, iv, 0);
}

int enc_ex(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
           uint8_t num_threads, uint8_t internal_threads, uint128_t iv,
           uint128_t starting_counter) {
        // TODO: obtain correct number of internal-external threads
        return keymix_ex(seed, seed_size, in, out, size, config, num_threads, internal_threads, iv,
                         true, starting_counter);
}
