#include "keymix.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "types.h"
#include "utils.h"

void keymix_inner(byte *seed, byte *out, size_t size, mixing_config *config, uint8_t levels) {
        (*(config->mixfunc))(seed, out, size);
        for (uint8_t l = 1; l < levels; l++) {
                spread_inplace(out, size, l, config->diff_factor);
                (*(config->mixfunc))(out, out, size);
        }
}

void *w_thread_keymix(void *a) {
        thread_data *args = (thread_data *)a;
        int err;

        // No need to sync among other threads here
        keymix_inner(args->in, args->out, args->thread_chunk_size, args->mixconfig,
                     args->thread_levels);

        int8_t nof_threads = args->seed_size / args->thread_chunk_size;

        _log(LOG_DEBUG, "thread %d finished the layers without coordination\n", args->thread_id);

        // Synchronized layers
        for (uint8_t l = args->thread_levels; l < args->total_levels; l++) {
                // Wait for all threads to finish the encryption step
                err = barrier(args->barrier, nof_threads);
                if (err) {
                        _log(LOG_ERROR, "thread %d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "thread %d: sychronized swap (level %d)\n", args->thread_id, l - 1);
                spread_chunks_inplace(args, l);

                // Wait for all threads to finish the swap step
                err = barrier(args->barrier, nof_threads);
                if (err) {
                        _log(LOG_ERROR, "thread %d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "thread %d: sychronized encryption (level %d)\n", args->thread_id,
                     l);
                err = (*(args->mixconfig->mixfunc))(args->out, args->out, args->thread_chunk_size);
                if (err) {
                        _log(LOG_ERROR, "thread %d: mixfunc error %d\n", args->thread_id, err);
                        goto thread_exit;
                }
        }

thread_exit:
        return NULL;
}

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config, uint8_t nof_threads) {
        if (!ISPOWEROF(nof_threads, config->diff_factor) || nof_threads == 0) {
                _log(LOG_DEBUG, "Unsupported number of threads, use a power of %u\n",
                     config->diff_factor);
                return 1;
        }

        // We can't assign more than 1 thread to a single macro, so we will
        // never spawn more than nof_macros threads
        uint64_t nof_macros = seed_size / SIZE_MACRO;
        nof_threads         = MIN(nof_threads, nof_macros);
        uint8_t levels      = total_levels(seed_size, config->diff_factor);

        _log(LOG_DEBUG, "total levels:\t\t%d\n", levels);

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                keymix_inner(seed, out, seed_size, config, levels);
                return 0;
        }

        size_t thread_chunk_size = seed_size / nof_threads;
        uint8_t thread_levels    = total_levels(thread_chunk_size, config->diff_factor);

        _log(LOG_DEBUG, "thread levels:\t\t%d\n", thread_levels);

        int err = 0;
        pthread_t threads[nof_threads];
        thread_data args[nof_threads];
        barrier_status barrier;

        // Initialize barrier once for all threads
        err = barrier_init(&barrier);
        if (err) {
                _log(LOG_ERROR, "barrier_init error %d\n", err);
                goto cleanup;
        }

        for (uint8_t t = 0; t < nof_threads; t++) {
                args[t].thread_id = t;
                args[t].barrier   = &barrier;
                args[t].in        = seed + t * thread_chunk_size;
                args[t].out       = out + t * thread_chunk_size;

                args[t].abs_in  = seed;
                args[t].abs_out = out;

                args[t].seed_size         = seed_size;
                args[t].thread_chunk_size = thread_chunk_size;
                args[t].thread_levels     = thread_levels;
                args[t].total_levels      = levels;
                args[t].mixconfig         = config;
        }

        _log(LOG_DEBUG, "[i] spawning the threads\n");
        for (uint8_t t = 0; t < nof_threads; t++) {
                err = pthread_create(&threads[t], NULL, w_thread_keymix, &args[t]);
                if (err) {
                        _log(LOG_ERROR, "pthread_create error %d\n", err);
                        goto cleanup;
                }
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");

        for (uint8_t t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        _log(LOG_ERROR, "pthread_join error %d (thread %d)\n", err, t);
                        goto cleanup;
                }
        }

cleanup:
        _log(LOG_DEBUG, "[i] safe obj destruction\n");
        err = barrier_destroy(&barrier);
        if (err) {
                _log(LOG_ERROR, "barrier_destroy error %d\n", err);
        }
        return err;
}
