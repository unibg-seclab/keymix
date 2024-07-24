#include "keymix.h"

#include "config.h"
#include "types.h"
#include "utils.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

void keymix_inner(byte *seed, byte *out, size_t size, mixing_config *config,
                  uint32_t levels) {
        (*(config->mixfunc))(seed, out, size);
        for (uint32_t l = 1; l < levels; l++) {
                spread_inplace(out, size, l, config->diff_factor);
                (*(config->mixfunc))(out, out, size);
        }
}

void *w_thread_keymix(void *a) {
        thread_data *args = (thread_data *)a;

        // No need to sync among other threads here
        keymix_inner(args->in, args->out, args->thread_chunk_size, args->mixconfig,
                     args->thread_levels);

        // notify the main thread to start the remaining levels
        _log(LOG_DEBUG, "thread %d finished the thread-layers\n", args->thread_id);
        if (args->thread_levels != args->total_levels) {
                sem_post(args->coord_sem);
        }

        // synchronized encryption layers
        for (uint32_t l = args->thread_levels; l < args->total_levels; l++) {
                // synchronized swap
                sem_wait(args->thread_sem);
                _log(LOG_DEBUG, "thread %d sychronized swap, level %d\n", args->thread_id, l - 1);
                if (!args->mixconfig->inplace) {
                        spread_chunks_inplace(args, l);
                }

                // notify the main thread that swap has finished
                sem_post(args->coord_sem);
                _log(LOG_DEBUG, "thread %d notified the coordinator after swap\n", args->thread_id);

                // synchronized encryption
                sem_wait(args->thread_sem);
                _log(LOG_DEBUG, "thread %d sychronized encryption, level %d\n", args->thread_id, l);
                int err = (*(args->mixconfig->mixfunc))(args->out, args->out, args->thread_chunk_size);
                if (err) {
                        _log(LOG_DEBUG, "thread %d, error from mixfunc %d\n", args->thread_id, err);
                        goto thread_exit;
                }
                // notify the main thread that everything for this level has finished
                sem_post(args->coord_sem);
                _log(LOG_DEBUG, "thread %d notified the coordinator after encryption\n",
                     args->thread_id);
        }

thread_exit:
        return NULL;
}

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config, uint32_t nof_threads) {
        if (!ISPOWEROF(nof_threads, config->diff_factor) || nof_threads == 0) {
                _log(LOG_DEBUG, "Unsupported number of threads, use a power of %u\n",
                     config->diff_factor);
                return 1;
        }

        // We can't assign more than 1 thread to a single macro, so we will
        // never spawn more than nof_macros threads
        uint64_t nof_macros = seed_size / SIZE_MACRO;
        nof_threads         = MIN(nof_threads, nof_macros);
        uint32_t levels     = total_levels(seed_size, config->diff_factor);

        _log(LOG_DEBUG, "total levels:\t\t%d\n", levels);

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                keymix_inner(seed, out, seed_size, config, levels);
                return 0;
        }

        size_t thread_chunk_size = seed_size / nof_threads;
        uint32_t thread_levels   = total_levels(thread_chunk_size, config->diff_factor);

        _log(LOG_DEBUG, "thread levels:\t\t%d\n", thread_levels);

        int err = 0;
        pthread_t threads[nof_threads];
        thread_data args[nof_threads];

        for (uint32_t t = 0; t < nof_threads; t++) {
                args[t].thread_id  = t;
                args[t].thread_sem = malloc(sizeof(sem_t));
                if (args[t].thread_sem == NULL) {
                        err         = ENOMEM;
                        nof_threads = t; // shorten the list to be cleaned
                        goto cleanup;
                }
                if (sem_init(args[t].thread_sem, 0, 0)) {
                        _log(LOG_DEBUG, "sem_init error (thread_sem), try again\n");
                        err         = errno;
                        nof_threads = t;
                        goto cleanup;
                }
                args[t].coord_sem = malloc(sizeof(sem_t));
                if (args[t].coord_sem == NULL) {
                        err         = ENOMEM;
                        nof_threads = t;
                        goto cleanup;
                }
                if (sem_init(args[t].coord_sem, 0, 0)) {
                        _log(LOG_DEBUG, "sem_init error (coord_sem), try again\n");
                        err         = errno;
                        nof_threads = t;
                        goto cleanup;
                }
                args[t].in  = seed + t * thread_chunk_size;
                args[t].out = out + t * thread_chunk_size;

                args[t].abs_in  = seed;
                args[t].abs_out = out;

                args[t].seed_size         = seed_size;
                args[t].thread_chunk_size = thread_chunk_size;
                args[t].thread_levels     = thread_levels;
                args[t].total_levels      = levels;
                args[t].mixconfig         = config;
        }

        _log(LOG_DEBUG, "[i] spawning the threads\n");
        for (uint32_t t = 0; t < nof_threads; t++) {
                err = pthread_create(&threads[t], NULL, w_thread_keymix, &args[t]);
                if (err) {
                        _log(LOG_DEBUG, "pthread_create error %d\n", err);
                        goto cleanup;
                }
        }

        _log(LOG_DEBUG, "[i] init parent swapping procedure\n");
        if (thread_levels != levels) {
                for (uint32_t l = 0; l < (levels - thread_levels) * 2 + 1; l++) {
                        uint32_t thr_i           = 0;
                        uint32_t waiting_threads = 0;

                        // wait until all the threads have completed the levels
                        for (int i = 0; i < nof_threads; i++)
                                sem_wait(args[i].coord_sem);

                        uint32_t level = thread_levels + l / 2;
                        if (l % 2 == 0 && level < total_levels && config->inplace) {
                                // For the moment let's keep the inplace swap among threads simple
                                // by running it centralized in the parent thread
                                spread_inplace(out, seed_size, level, config->diff_factor);
                        }

                        // synchronization is done, notify the threads back
                        for (uint32_t t = 0; t < nof_threads; t++) {
                                err = sem_post(args[t].thread_sem);
                                if (err) {
                                        _log(LOG_DEBUG, "coordinator, sem_post error %d\n", errno);
                                        goto cleanup;
                                }
                        }
                        _log(LOG_DEBUG, "[i] coordinator notified all the threads\n");
                }
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");

        for (uint32_t t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        _log(LOG_DEBUG, "pthread_join error %d (thread %d)\n", err, t);
                        goto cleanup;
                }
        }

cleanup:
        _log(LOG_DEBUG, "[i] safe obj destruction\n");
        for (uint32_t i = 0; i < nof_threads; i++) {
                if (!sem_destroy(args[i].coord_sem)) {
                        free(args[i].coord_sem);
                } else {
                        _log(LOG_DEBUG, "sem_free error %d\n", errno);
                }
                if (!sem_destroy(args[i].thread_sem)) {
                        free(args[i].thread_sem);
                } else {
                        _log(LOG_DEBUG, "sem_free error %d\n", errno);
                }
        }
        return err;
}
