#include "keymix.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ctx.h"
#include "config.h"
#include "log.h"
#include "spread.h"
#include "types.h"
#include "utils.h"

// --------------------------------------------------------- Types for threading

typedef struct {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        int8_t nof_waiting_thread;
        int8_t round;
} thr_barrier_t;

typedef struct {
        uint8_t id;
        uint8_t nof_threads;
        thr_barrier_t *barrier;
        ctx_t *ctx;
        byte *in;
        byte *out;
        byte *abs_out;
        size_t chunk_size;
        size_t total_size;
        uint8_t sync_levels;
        uint8_t total_levels;
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

int get_fanouts_from_block_size(block_size_t block_size, uint8_t n, uint8_t *fanouts) {
        uint8_t chunk_size = (block_size == 16 ? 8 : 16);
        uint8_t count = 0;

        for (uint8_t fanout = block_size / chunk_size; fanout >= 2; fanout--) {
                if (block_size % fanout)
                        continue;

                fanouts[count++] = fanout;

                if (count == n)
                        break;
        }

        return count;
}

int get_fanouts_from_mix_type(mix_impl_t mix_type, uint8_t n, uint8_t *fanouts) {
        mix_func_t mix_func;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix_func, &block_size)) {
                return -1;
        }

        return get_fanouts_from_block_size(block_size, n, fanouts);
}

inline uint8_t get_levels(size_t size, block_size_t block_size, uint8_t fanout) {
        uint64_t nof_macros = size / block_size;
        return 1 + LOGBASE(nof_macros, fanout);
}

void keymix_inner(ctx_t *ctx, byte* in, byte* out, size_t size, uint8_t levels) {
        spread_args_t args = {
                .thread_id       = 0,
                .nof_threads     = 1,
                .buffer          = out,
                .buffer_abs      = out,
                .buffer_abs_size = size,
                .buffer_size     = size,
                .fanout          = ctx->fanout,
                .block_size      = ctx->block_size,
        };

        (*ctx->mixpass)(in, out, size);
        for (args.level = 1; args.level < levels; args.level++) {
                spread(&args);
                (*ctx->mixpass)(out, out, size);
        }
}

// The input of the optimized version is not the key itself, but the result of
// its precomputation.
// When the operation is requested inplace (i.e., in == out), we overwrite the
// state, so we expect copies of the original state have been made by the
// caller. On the other hand, when they are not inplace the input shall not be
// be changed.
void keymix_inner_opt(ctx_t *ctx, byte* in, byte* out, size_t size, uint8_t levels) {
        size_t curr_size = ctx->block_size;

        spread_args_t args = {
                .thread_id       = 0,
                .nof_threads     = 1,
                .buffer          = out,
                .buffer_abs      = out,
                .buffer_abs_size = size,
                .buffer_size     = size,
                .fanout          = ctx->fanout,
                .block_size      = ctx->block_size,
        };

        if (in != out) {
                memcpy(out, in, size);
        }

        (*ctx->mixpass)(in, out, curr_size);
        for (args.level = 1; args.level < levels; args.level++) {
                curr_size *= ctx->fanout;
                args.buffer_abs_size = curr_size;
                args.buffer_size     = curr_size;
                spread(&args);
                (*ctx->mixpass)(out, out, curr_size);
        }
}

// --------------------------------------------------------- Actual threaded keymix

void *w_thread_keymix(void *a) {
        thr_keymix_t *thr     = (thr_keymix_t *)a;
        ctx_t *ctx            = thr->ctx;

        uint8_t unsync_levels = thr->total_levels - thr->sync_levels;

        // No need to sync among other threads here
        keymix_inner(thr->ctx, thr->in, thr->out, thr->chunk_size, unsync_levels);
        _log(LOG_DEBUG, "t=%d: finished layers without coordination\n", thr->id);

        // Synchronized layers

        spread_args_t args = {
                .thread_id       = thr->id,
                .nof_threads     = thr->nof_threads,
                .buffer          = thr->out,
                .buffer_abs      = thr->abs_out,
                .buffer_abs_size = thr->total_size,
                .buffer_size     = thr->chunk_size,
                .fanout          = ctx->fanout,
                .block_size      = ctx->block_size,
                .level           = unsync_levels,
        };

        for (; args.level < thr->total_levels; args.level++) {
                _log(LOG_DEBUG, "t=%d: notified the coordinator\n", thr->id);
                // Wait for all threads to finish the encryption step
                int err = barrier(thr->barrier, thr->nof_threads);
                if (err) {
                        _log(LOG_ERROR, "t=%d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "t=%d: sychronized swap (level %d)\n",
                     thr->id, args.level - 1);
                spread(&args); // always called with at least 1 level

                // Wait for all threads to finish the swap step
                err = barrier(thr->barrier, thr->nof_threads);
                if (err) {
                        _log(LOG_ERROR, "t=%d: barrier error %d\n", err);
                        goto thread_exit;
                }

                _log(LOG_DEBUG, "t=%d: sychronized encryption (level %d)\n",
                     thr->id, args.level);
                err = (*(ctx->mixpass))(thr->out, thr->out, thr->chunk_size);
                if (err) {
                        _log(LOG_ERROR, "t=%d: mixpass error %d\n", thr->id, err);
                        goto thread_exit;
                }
        }

thread_exit:
        return NULL;
}

int keymix(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t nof_threads) {
        uint64_t tot_macros;
        uint64_t macros;
        uint8_t levels;
        uint8_t sync_levels;
        size_t thread_chunk_size;
        byte *offset;

        tot_macros = size / ctx->block_size;
        _log(LOG_DEBUG, "total macros:\t%d\n", tot_macros);
        levels     = get_levels(size, ctx->block_size, ctx->fanout);
        _log(LOG_DEBUG, "total levels:\t%d\n", levels);

        // Ensure 1 <= #threads <= #macros
        nof_threads = MAX(1, MIN(nof_threads, tot_macros));
        _log(LOG_DEBUG, "#threads:\t%d\n", nof_threads);

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                if (ctx->enc_mode != ENC_MODE_CTR_OPT) {
                        keymix_inner(ctx, in, out, size, levels);
                } else {
                        keymix_inner_opt(ctx, in, out, size, levels);
                }
                return 0;
        }

        // If the #threads is a power of the fanout, the threads won't write in
        // other threads memory up to the last few levels, so they can
        // initially run without syncronization and only then be syncronized on
        // the last few levels.
        // NOTE: The 1st layer of encryption can always be done unsyncronized.
        sync_levels = levels - 1;
        if (ISPOWEROF(nof_threads, ctx->fanout)) {
                sync_levels = LOGBASE(nof_threads, ctx->fanout);
        }
        _log(LOG_DEBUG, "sync levels:\t%d\n", sync_levels);

        pthread_t threads[nof_threads];
        thr_keymix_t args[nof_threads];
        thr_barrier_t barrier;

        // Initialize barrier once for all threads
        int err = 0;
        err = barrier_init(&barrier);
        if (err) {
                _log(LOG_ERROR, "barrier_init error %d\n", err);
                goto cleanup;
        }

        offset = out;

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_keymix_t *a = args + t;

                macros = tot_macros / nof_threads + (t < tot_macros % nof_threads);
                thread_chunk_size = ctx->block_size * macros;

                a->id           = t;
                a->nof_threads  = nof_threads;
                a->barrier      = &barrier;
                a->ctx          = ctx;
                a->in           = in;
                a->abs_out      = out;
                a->out          = offset;
                a->chunk_size   = thread_chunk_size;
                a->total_size   = size;
                a->sync_levels  = sync_levels;
                a->total_levels = levels;

                pthread_create(&threads[t], NULL, w_thread_keymix, a);

                in += thread_chunk_size;
                offset += thread_chunk_size;
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
