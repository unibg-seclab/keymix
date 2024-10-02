#include "keymix.h"

#include "config.h"
#include "log.h"
#include "spread.h"
#include "types.h"
#include "utils.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

// --------------------------------------------------------- Types for threading

typedef struct {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        int8_t nof_waiting_thread;
        int8_t round;
} thr_barrier_t;

typedef struct {
        uint8_t id;
        byte *in;
        byte *out;
        byte *abs_out;
        size_t total_size;
        size_t chunk_size;
        uint8_t thread_levels;
        uint8_t total_levels;
        mixpass_impl_t mixpass;
        uint8_t fanout;
        thr_barrier_t *barrier;
} thr_keymix_t;

// --------------------------------------------------------- Threading barrier code

int barrier_init(thr_barrier_t *state) {
        int err = pthread_mutex_init(&state->mutex, NULL);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_init error %d\n", err);
                return err;
        }
        err = pthread_cond_init(&state->cond, NULL);
        if (err) {
                _log(LOG_ERROR, "pthread_cond_init error %d\n", err);
                return err;
        }
        state->nof_waiting_thread = 0;
        state->round              = 0;
        return 0;
}

int barrier(thr_barrier_t *state, int8_t nof_threads) {
        int err = pthread_mutex_lock(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_lock error %d", err);
                return err;
        }

        if (++state->nof_waiting_thread == nof_threads) {
                // Wake up every thread sleeping on cond
                state->round++;
                state->nof_waiting_thread = 0;
                err                       = pthread_cond_broadcast(&state->cond);
                if (err) {
                        _log(LOG_ERROR, "pthread_cond_broadcast error %d", err);
                        return err;
                }
        } else {
                // Sleep until the next round starts
                int8_t round = state->round;
                do {
                        err = pthread_cond_wait(&state->cond, &state->mutex);
                        if (err) {
                                _log(LOG_ERROR, "pthread_cond_wait error %d", err);
                                return err;
                        }
                } while (round == state->round);
        }

        err = pthread_mutex_unlock(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_unlock error %d", err);
                return err;
        }

        return 0;
}

int barrier_destroy(thr_barrier_t *state) {
        int err = pthread_mutex_destroy(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_destroy error %d\n", err);
                return err;
        }

        err = pthread_cond_destroy(&state->cond);
        if (err) {
                _log(LOG_ERROR, "pthread_cond_destroy error %d\n", err);
                return err;
        }

        return 0;
}

// --------------------------------------------------------- Some utility functions

int get_available_fanouts(uint8_t n, uint8_t *fanouts) {
        uint8_t count = 0;
        for (uint8_t fanout = BLOCK_SIZE / CHUNK_SIZE; fanout >= 2; fanout--) {
                if (BLOCK_SIZE % fanout)
                        continue;

                fanouts[count++] = fanout;

                if (count == n)
                        break;
        }

        return count;
}

inline uint8_t total_levels(size_t size, uint8_t fanout) {
        uint64_t nof_macros = size / BLOCK_SIZE;
        return 1 + LOGBASE(nof_macros, fanout);
}

void keymix_inner(mixpass_impl_t mixpass, byte *in, byte *out, size_t size, uint8_t fanout,
                  uint8_t levels) {
        (*mixpass)(in, out, size);
        for (uint8_t l = 1; l < levels; l++) {
                spread(out, size, l, fanout);
                (*mixpass)(out, out, size);
        }
}

// --------------------------------------------------------- Actual threaded keymix

void *w_thread_keymix(void *a) {
        thr_keymix_t *args = (thr_keymix_t *)a;
        int8_t nof_threads = args->total_size / args->chunk_size;

        // No need to sync among other threads here
        keymix_inner(args->mixpass, args->in, args->out, args->chunk_size, args->fanout,
                     args->thread_levels);

        _log(LOG_DEBUG, "thread %d finished the layers without coordination\n", args->id);

        // Synchronized layers
        for (uint8_t l = args->thread_levels; l < args->total_levels; l++) {
                _log(LOG_DEBUG, "thread %d notified the coordinator after encryption\n", args->id);
                // Wait for all threads to finish the encryption step
                int err = barrier(args->barrier, nof_threads);
                if (err) {
                        _log(LOG_ERROR, "thread %d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "thread %d: sychronized swap (level %d)\n", args->id, l - 1);
                spread_chunks_args_t thrdata = {
                    .thread_id       = args->id,
                    .buffer          = args->out,
                    .buffer_abs      = args->abs_out,
                    .buffer_abs_size = args->total_size,
                    .buffer_size     = args->chunk_size,
                    .thread_levels   = args->thread_levels,
                    .total_levels    = args->total_levels,
                    .fanout          = args->fanout,
                    .level           = l,
                };
                spread_chunks(&thrdata);

                // Wait for all threads to finish the swap step
                err = barrier(args->barrier, nof_threads);
                if (err) {
                        _log(LOG_ERROR, "thread %d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "thread %d: sychronized encryption (level %d)\n", args->id, l);
                err = (*(args->mixpass))(args->out, args->out, args->chunk_size);
                if (err) {
                        _log(LOG_ERROR, "thread %d: mixfunc error %d\n", args->id, err);
                        goto thread_exit;
                }
        }

thread_exit:
        return NULL;
}

int keymix(mixpass_impl_t mixpass, byte *in, byte *out, size_t size, uint8_t fanout,
           uint8_t nof_threads) {
        if (!ISPOWEROF(nof_threads, fanout) || nof_threads == 0) {
                _log(LOG_DEBUG, "Unsupported number of threads, use a power of %u\n", fanout);
                return 1;
        }

        // We can't assign more than 1 thread to a single macro, so we will
        // never spawn more than nof_macros threads
        uint64_t nof_macros = size / BLOCK_SIZE;
        nof_threads         = MIN(nof_threads, nof_macros);
        uint8_t levels      = total_levels(size, fanout);

        _log(LOG_DEBUG, "total levels:\t\t%d\n", levels);

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                keymix_inner(mixpass, in, out, size, fanout, levels);
                return 0;
        }

        size_t thread_chunk_size = size / nof_threads;
        uint8_t thread_levels    = total_levels(thread_chunk_size, fanout);

        _log(LOG_DEBUG, "thread levels:\t\t%d\n", thread_levels);

        int err = 0;
        pthread_t threads[nof_threads];
        thr_keymix_t args[nof_threads];
        thr_barrier_t barrier;

        // Initialize barrier once for all threads
        err = barrier_init(&barrier);
        if (err) {
                _log(LOG_ERROR, "barrier_init error %d\n", err);
                goto cleanup;
        }

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_keymix_t *a = args + t;
                a->id           = t;
                a->in           = in + t * thread_chunk_size;
                a->out          = out + t * thread_chunk_size;
                a->barrier      = &barrier;

                a->abs_out = out;

                a->total_size    = size;
                a->chunk_size    = thread_chunk_size;
                a->thread_levels = thread_levels;
                a->total_levels  = levels;
                a->mixpass    = mixpass;
                a->fanout        = fanout;

                pthread_create(&threads[t], NULL, w_thread_keymix, a);
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
        if (err)
                _log(LOG_ERROR, "barrier_destroy error %d\n", err);

        return err;
}
