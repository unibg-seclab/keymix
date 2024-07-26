#include "keymix.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "types.h"
#include "utils.h"

typedef struct {
        uint8_t id;
        sem_t *sem_thread_can_work;
        sem_t *sem_done;
        byte *in;
        byte *out;
        byte *abs_out;
        size_t total_size;
        size_t chunk_size;
        uint8_t thread_levels;
        uint8_t total_levels;
        mixctrpass_impl_t mixctrpass;
        uint8_t fanout;
} thr_keymix_t;

void keymix_inner(mixctrpass_impl_t mixctrpass, byte *seed, byte *out, size_t size, uint8_t fanout,
                  uint8_t levels) {
        (*mixctrpass)(seed, out, size);
        for (uint8_t l = 1; l < levels; l++) {
                spread_inplace(out, size, l, fanout);
                (*mixctrpass)(out, out, size);
        }
}

void *w_thread_keymix(void *a) {
        thr_keymix_t *args = (thr_keymix_t *)a;

        // No need to sync among other threads here
        keymix_inner(args->mixctrpass, args->in, args->out, args->chunk_size, args->fanout,
                     args->thread_levels);

        // notify the main thread to start the remaining levels
        _log(LOG_DEBUG, "thread %d finished the thread-layers\n", args->id);
        if (args->thread_levels != args->total_levels) {
                sem_post(args->sem_done);
        }

        // synchronized encryption layers
        for (uint8_t l = args->thread_levels; l < args->total_levels; l++) {
                // synchronized swap
                sem_wait(args->sem_thread_can_work);
                _log(LOG_DEBUG, "thread %d sychronized swap, level %d\n", args->id, l - 1);
                spread_inplace_chunks_t thrdata = {
                    .thread_id       = args->id,
                    .buffer          = args->out,
                    .buffer_abs      = args->abs_out,
                    .buffer_abs_size = args->total_size,
                    .buffer_size     = args->chunk_size,
                    .thread_levels   = args->thread_levels,
                    .total_levels    = args->total_levels,
                    .fanout          = args->fanout,
                };
                spread_chunks_inplace(&thrdata, l);

                // notify the main thread that swap has finished
                sem_post(args->sem_done);
                _log(LOG_DEBUG, "thread %d notified the coordinator after swap\n", args->id);

                // synchronized encryption
                sem_wait(args->sem_thread_can_work);
                _log(LOG_DEBUG, "thread %d sychronized encryption, level %d\n", args->id, l);
                int err = (*(args->mixctrpass))(args->out, args->out, args->chunk_size);
                if (err) {
                        _log(LOG_ERROR, "thread %d, error from mixfunc %d\n", args->id, err);
                        goto thread_exit;
                }
                // notify the main thread that everything for this level has finished
                sem_post(args->sem_done);
                _log(LOG_DEBUG, "thread %d notified the coordinator after encryption\n", args->id);
        }

thread_exit:
        return NULL;
}

int keymix(mixctrpass_impl_t mixctrpass, byte *seed, byte *out, size_t seed_size, uint8_t fanout,
           uint8_t nof_threads) {
        if (!ISPOWEROF(nof_threads, fanout) || nof_threads == 0) {
                _log(LOG_DEBUG, "Unsupported number of threads, use a power of %u\n", fanout);
                return 1;
        }

        // We can't assign more than 1 thread to a single macro, so we will
        // never spawn more than nof_macros threads
        uint64_t nof_macros = seed_size / SIZE_MACRO;
        nof_threads         = MIN(nof_threads, nof_macros);
        uint8_t levels      = total_levels(seed_size, fanout);

        _log(LOG_DEBUG, "total levels:\t\t%d\n", levels);

        mixing_config config = {mixctrpass, fanout};

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                keymix_inner(mixctrpass, seed, out, seed_size, fanout, levels);
                return 0;
        }

        size_t thread_chunk_size = seed_size / nof_threads;
        uint8_t thread_levels    = total_levels(thread_chunk_size, fanout);

        _log(LOG_DEBUG, "thread levels:\t\t%d\n", thread_levels);

        int err = 0;
        pthread_t threads[nof_threads];
        thr_keymix_t args[nof_threads];

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_keymix_t *a        = args + t;
                a->id                  = t;
                a->sem_thread_can_work = malloc(sizeof(sem_t));
                a->sem_done            = malloc(sizeof(sem_t));
                a->in                  = seed + t * thread_chunk_size;
                a->out                 = out + t * thread_chunk_size;

                a->abs_out = out;

                a->total_size    = seed_size;
                a->chunk_size    = thread_chunk_size;
                a->thread_levels = thread_levels;
                a->total_levels  = levels;
                a->mixctrpass    = mixctrpass;
                a->fanout        = fanout;

                sem_init(args[t].sem_thread_can_work, 0, 0);
                sem_init(args[t].sem_done, 0, 0);

                pthread_create(&threads[t], NULL, w_thread_keymix, a);
        }

        _log(LOG_DEBUG, "[i] init parent swapping procedure\n");
        if (thread_levels != levels) {
                for (uint8_t l = 0; l < (levels - thread_levels) * 2 + 1; l++) {
                        // wait until all the threads have completed the levels
                        for (uint8_t t = 0; t < nof_threads; t++)
                                sem_wait(args[t].sem_done);

                        // synchronization is done, notify the threads back
                        for (uint8_t t = 0; t < nof_threads; t++)
                                sem_post(args[t].sem_thread_can_work);

                        _log(LOG_DEBUG, "[i] coordinator notified all the threads\n");
                }
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");

        for (uint8_t t = 0; t < nof_threads; t++) {
                pthread_join(threads[t], NULL);
        }

cleanup:
        _log(LOG_DEBUG, "[i] safe obj destruction\n");
        for (uint8_t t = 0; t < nof_threads; t++) {
                if (args[t].sem_done) {
                        sem_destroy(args[t].sem_done);
                        free(args[t].sem_done);
                }
                if (args[t].sem_thread_can_work) {
                        sem_destroy(args[t].sem_thread_can_work);
                        free(args[t].sem_thread_can_work);
                }
        }
        return err;
}
