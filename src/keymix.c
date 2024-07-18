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
        byte *buffer = (byte *)malloc(seed_size);

        size_t nof_macros   = seed_size / SIZE_MACRO;
        unsigned int levels = 1 + LOGBASE(nof_macros, config->diff_factor);

        (*(config->mixfunc))(seed, out, seed_size);

        for (unsigned int level = 1; level < levels; level++) {
                shuffle_opt(buffer, out, seed_size, level, config->diff_factor);
                (*(config->mixfunc))(buffer, out, seed_size);
        }

        explicit_bzero(buffer, seed_size);
        free(buffer);
        return 0;
}

// -------------------------------- Multi-threaded keymix

#define WAIT(action)                                                                               \
        ({                                                                                         \
                int _err;                                                                          \
                while (1) {                                                                        \
                        _err = action;                                                             \
                        if (_err == 0)                                                             \
                                break;                                                             \
                }                                                                                  \
                _err;                                                                              \
        })

void *run(void *config) {
        thread_data *args = (thread_data *)config;
        int *err          = malloc(sizeof(int));
        if (err == NULL) {
                D LOG("thread %d crashed at init time\n", args->thread_id);
                goto thread_exit;
        }
        *err = 0;

        // No need to sync among other threads here
        keymix(args->in, args->out, args->thread_chunk_size, args->mixconfig);

        // notify the main thread to start the remaining levels
        D LOG("thread %d finished the thread-layers\n", args->thread_id);
        if (args->thread_levels != args->total_levels) {
                WAIT(sem_post(args->coord_sem));
        }
        // synchronized encryption layers
        for (unsigned int l = args->thread_levels; l < args->total_levels; l++) {
                *err = 0;
                // synchronized swap
                *err = WAIT(sem_wait(args->thread_sem));
                D LOG("thread %d sychronized swap, level %d\n", args->thread_id, l - 1);
                shuffle_chunks(args, l);

                // notify the main thread that swap has finished
                *err = WAIT(sem_post(args->coord_sem));
                D LOG("thread %d notified the coordinator after swap\n", args->thread_id);

                // synchronized encryption
                *err = WAIT(sem_wait(args->thread_sem));
                D LOG("thread %d sychronized encryption, level %d\n", args->thread_id, l);
                *err = (*(args->mixconfig->mixfunc))(args->buf, args->out, args->thread_chunk_size);
                if (*err) {
                        goto thread_exit;
                }
                // notify the main thread that everything for this level has finished
                *err = WAIT(sem_post(args->coord_sem));
                D LOG("thread %d notified the coordinator after encryption\n", args->thread_id);
        }

thread_exit:
        pthread_exit(err);
}

#undef WAIT

// Mixes the seed into out using a number of threads equal to a power of diff_factor
int parallel_keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config,
                    unsigned int nof_threads) {
        if (!ISPOWEROF(nof_threads, config->diff_factor)) {
                D LOG("Unsupported number of threads, use a power of %u\n", config->diff_factor);
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

        D LOG("thread levels:\t\t%d\n", thread_levels);
        D LOG("total levels:\t\t%d\n", total_levels);

        pthread_t threads[nof_threads];
        thread_data args[nof_threads];
        size_t thread_chunk_size = seed_size / nof_threads;

        byte *buffer = malloc(seed_size);
        if (buffer == NULL) {
                D LOG("Cannot allocate more memory\n");
                goto cleanup;
        }

        D LOG("[i] preparing the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
                args[t].thread_id  = t;
                args[t].thread_sem = malloc(sizeof(sem_t));
                if (args[t].thread_sem == NULL) {
                        err         = ENOMEM;
                        nof_threads = t; // shorten the list to be cleaned
                        goto cleanup;
                }
                if (sem_init(args[t].thread_sem, 0, 0)) {
                        D LOG("sem_init error (thread_sem), try again\n");
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
                        D LOG("sem_init error (coord_sem), try again\n");
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

        D LOG("[i] spawning the threads\n");
        for (unsigned int t = 0; t < nof_threads; t++) {
                err = pthread_create(&threads[t], NULL, run, &args[t]);
                if (err) {
                        D LOG("pthread_create error %d\n", err);
                        goto cleanup;
                }
        }

        D LOG("[i] init parent swapping procedure\n");

        // todo: implement timeout fail
        if (thread_levels != total_levels) {
                for (unsigned int l = 0; l < (total_levels - thread_levels) * 2 + 1; l++) {
                        unsigned int thr_i           = 0;
                        unsigned int waiting_threads = 0;

                        // wait until all the threads have completed the levels
                        while (1) {
                                // todo: move its memory to other threads
                                if (sem_trywait(args[thr_i].coord_sem) == 0) {
                                        D LOG("[i] thread %d waiting...\n", thr_i);
                                        waiting_threads++;
                                }
                                if (waiting_threads == nof_threads) {
                                        break;
                                }
                                thr_i++;
                                if (thr_i == nof_threads) {
                                        thr_i = 0;
                                }
                        }

                        for (unsigned int t = 0; t < nof_threads; t++) {
                                int semres;
                                do {
                                        semres = sem_post(args[t].thread_sem);
                                } while (semres != 0 && errno == EINTR);
                                if (semres == -1 && errno != EINTR) {
                                        D LOG("coordinator, sem_post error %d\n", errno);
                                        err = -1;
                                        goto cleanup;
                                }
                        }
                        D LOG("[i] coordinator notified all the threads\n");
                }
        }

        D LOG("[i] joining the threads...\n");
        // There is no use for a thread retval now (it was only allocated and then freed)
        for (unsigned int t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        D LOG("pthread_join error %d (thread %d)\n", err, t);
                        goto cleanup;
                }
        }

cleanup:
        D LOG("[i] safe obj destruction\n");
        explicit_bzero(buffer, seed_size);
        free(buffer);
        for (unsigned int i = 0; i < nof_threads; i++) {
                if (sem_destroy(args[i].coord_sem)) {
                        D LOG("sem_free error %d\n", errno);
                } else {
                        free(args[i].coord_sem);
                }
                if (sem_destroy(args[i].thread_sem)) {
                        D LOG("sem_free error %d\n", errno);
                } else {
                        free(args[i].thread_sem);
                }
        }
        return err;
}
