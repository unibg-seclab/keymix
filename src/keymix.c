#include "keymix.h"

#include "config.h"
#include "types.h"
#include "utils.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

// -------------------------------- Simple single-threaded keymix

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config) {
        byte *buffer = (!config->inplace ? (byte *)malloc(seed_size) : out);

        size_t nof_macros   = seed_size / SIZE_MACRO;
        unsigned int levels = 1 + LOGBASE(nof_macros, config->diff_factor);

        (*(config->mixfunc))(seed, out, seed_size);

        for (unsigned int level = 1; level < levels; level++) {
                if (!config->inplace) {
                        shuffle_opt(buffer, out, seed_size, level, config->diff_factor);
                } else {
                        spread_inplace(out, seed_size, level, config->diff_factor);
                }
                (*(config->mixfunc))(buffer, out, seed_size);
        }

        if (!config->inplace) {
                explicit_bzero(buffer, seed_size);
                free(buffer);
        }
        return 0;
}

// -------------------------------- Multi-threaded keymix

void *run(void *config) {
        thread_data *args = (thread_data *)config;
        int *err          = malloc(sizeof(int));
        if (err == NULL) {
                _log(LOG_DEBUG, "thread %d crashed at init time\n", args->thread_id);
                goto thread_exit;
        }
        *err = 0;

        // No need to sync among other threads here
        keymix(args->in, args->out, args->thread_chunk_size, args->mixconfig);

        // notify the main thread to start the remaining levels
        _log(LOG_DEBUG, "thread %d finished the thread-layers\n", args->thread_id);
        if (args->thread_levels != args->total_levels) {
                sem_post(args->coord_sem);
        }
        // synchronized encryption layers
        for (unsigned int l = args->thread_levels; l < args->total_levels; l++) {
                *err = 0;
                // synchronized swap
                sem_wait(args->thread_sem);
                _log(LOG_DEBUG, "thread %d sychronized swap, level %d\n", args->thread_id, l - 1);
                if (!args->mixconfig->inplace) {
                        shuffle_chunks(args, l);
                } else {
                        // TODO: Add inplace solution
                        spread_chunks(args, l);
                }

                // notify the main thread that swap has finished
                sem_post(args->coord_sem);
                _log(LOG_DEBUG, "thread %d notified the coordinator after swap\n", args->thread_id);

                // synchronized encryption
                sem_wait(args->thread_sem);
                _log(LOG_DEBUG, "thread %d sychronized encryption, level %d\n", args->thread_id, l);
                *err = (*(args->mixconfig->mixfunc))(args->buf, args->out, args->thread_chunk_size);
                if (*err) {
                        goto thread_exit;
                }
                // notify the main thread that everything for this level has finished
                sem_post(args->coord_sem);
                _log(LOG_DEBUG, "thread %d notified the coordinator after encryption\n",
                     args->thread_id);
        }

thread_exit:
        pthread_exit(err);
}

// Mixes the seed into out using a number of threads equal to a power of diff_factor
int parallel_keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config,
                    unsigned int nof_threads) {
        if (!ISPOWEROF(nof_threads, config->diff_factor)) {
                _log(LOG_DEBUG, "Unsupported number of threads, use a power of %u\n",
                     config->diff_factor);
                return EPERM;
        }

        int err = 0;

        size_t nof_macros = seed_size / SIZE_MACRO;
        // We can't assign more than 1 thread to a single macro, so we will
        // never spawn more than nof_macros threads
        nof_threads = MIN(nof_threads, nof_macros);

        unsigned int thread_levels =
            1 + LOGBASE((double)nof_macros / nof_threads, config->diff_factor);
        unsigned int total_levels = 1 + LOGBASE(nof_macros, config->diff_factor);

        _log(LOG_DEBUG, "thread levels:\t\t%d\n", thread_levels);
        _log(LOG_DEBUG, "total levels:\t\t%d\n", total_levels);

        pthread_t threads[nof_threads];
        thread_data args[nof_threads];
        size_t thread_chunk_size = seed_size / nof_threads;

        byte *buffer = malloc(seed_size);
        if (buffer == NULL) {
                _log(LOG_DEBUG, "Cannot allocate more memory\n");
                goto cleanup;
        }

        _log(LOG_DEBUG, "[i] preparing the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
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
                args[t].buf = buffer + t * thread_chunk_size;

                args[t].abs_in  = seed;
                args[t].abs_out = out;
                args[t].abs_buf = buffer;

                args[t].seed_size         = seed_size;
                args[t].thread_chunk_size = thread_chunk_size;
                args[t].thread_levels     = thread_levels;
                args[t].total_levels      = total_levels;
                args[t].mixconfig         = config;
        }

        _log(LOG_DEBUG, "[i] spawning the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
                err = pthread_create(&threads[t], NULL, run, &args[t]);
                if (err) {
                        _log(LOG_DEBUG, "pthread_create error %d\n", err);
                        goto cleanup;
                }
        }

        _log(LOG_DEBUG, "[i] init parent swapping procedure\n");

        // todo: implement timeout fail
        if (thread_levels != total_levels) {
                for (unsigned int l = 0; l < (total_levels - thread_levels) * 2 + 1; l++) {
                        unsigned int thr_i           = 0;
                        unsigned int waiting_threads = 0;

                        // wait until all the threads have completed the levels
                        for (int i = 0; i < nof_threads; i++)
                                sem_wait(args[i].coord_sem);

                        // synchronization is done, notify the threads back
                        for (unsigned int t = 0; t < nof_threads; t++) {
                                int semres = sem_post(args[t].thread_sem);
                                if (semres == -1) {
                                        _log(LOG_DEBUG, "coordinator, sem_post error %d\n", errno);
                                        err = -1;
                                        goto cleanup;
                                }
                        }
                        _log(LOG_DEBUG, "[i] coordinator notified all the threads\n");
                }
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");
        // There is no use for a thread retval now (it was only allocated and then freed)
        for (unsigned int t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        _log(LOG_DEBUG, "pthread_join error %d (thread %d)\n", err, t);
                        goto cleanup;
                }
        }

cleanup:
        _log(LOG_DEBUG, "[i] safe obj destruction\n");
        explicit_bzero(buffer, seed_size);
        free(buffer);
        for (unsigned int i = 0; i < nof_threads; i++) {
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
