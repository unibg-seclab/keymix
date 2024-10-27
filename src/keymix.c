#include "keymix.h"

#include <assert.h>
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
        uint8_t unsync_levels;
        uint8_t total_levels;
        byte *iv;
        uint32_t counter;
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

// --------------------------------------------------------- Single-threaded keymix

inline void _reverse32bits(uint32_t *x) {
        byte *data  = (byte *)x;
        size_t size = sizeof(*x);
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define __correct_endianness(...) _reverse32bits(__VA_ARGS_)
#else
#define __correct_endianness(...)
#endif

// Copy 1st block size of the key and update its 1st 128 bits as follows:
// - XOR IV with 1st 96 bits of the key
// - Sum counter to the following 32 bits of the key
// Then, encrypt the 1st block size, this is done to preserve the key and avoid
// allocating extra memory
void update_iv_counter_block(ctx_t *ctx, byte *in, byte *out, byte*iv,
                             uint32_t counter) {
        byte block[ctx->block_size];
        uint32_t *counter_ptr;

        memcpy(block, in, ctx->block_size);
        memxor(block, block, iv, KEYMIX_IV_SIZE);
        counter_ptr = (uint32_t *)(block + KEYMIX_IV_SIZE);
        __correct_endianness(counter_ptr);
        (*counter_ptr) += counter;
        __correct_endianness(counter_ptr);
        (*ctx->mixpass)(block, out, ctx->block_size);
}

void keymix_inner(ctx_t *ctx, byte* in, byte* out, size_t size, byte* iv,
                  uint32_t counter, uint8_t levels) {
        byte *out_first   = out;
        size_t size_first = size;

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

        if (iv) {
                // Update 1st block with IV and counter on its own
                update_iv_counter_block(ctx, in, out, iv, counter);

                // Skip 1st block with 1st encryption level
                in += ctx->block_size;
                out_first += ctx->block_size;
                size_first -= ctx->block_size;
        }

        (*ctx->mixpass)(in, out_first, size_first);
        for (args.level = 1; args.level < levels; args.level++) {
                spread_opt(&args);
                (*ctx->mixpass)(out, out, size);
        }
}

// The input of the optimized version is not the key itself, but the result of
// its precomputation.
// When the operation is requested inplace (i.e., in == out), we overwrite the
// state, so we expect copies of the original state have been made by the
// caller. On the other hand, when they are not inplace the input shall not be
// be changed.
void keymix_inner_opt(ctx_t *ctx, byte* in, byte* out, size_t size, byte* iv,
                      uint32_t counter, uint8_t levels) {
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

        // 1st level
        if (iv) {
                // Update 1st block with IV and counter on its own
                update_iv_counter_block(ctx, in, out, iv, counter);
        } else {
                // Encrypt 1st block as is
                (*ctx->mixpass)(in, out, curr_size);
        }

        // Other levels
        for (args.level = 1; args.level < levels; args.level++) {
                curr_size *= ctx->fanout;
                args.buffer_abs_size = curr_size;
                args.buffer_size     = curr_size;
                spread_opt(&args);
                (*ctx->mixpass)(out, out, curr_size);
        }
}

// --------------------------------------------------------- Multi-threaded keymix

void *w_thread_keymix(void *a) {
        thr_keymix_t *thr     = (thr_keymix_t *)a;
        ctx_t *ctx            = thr->ctx;
        byte *iv              = (!thr->id ? thr->iv : NULL);
        uint32_t counter      = (!thr->id ? thr->counter : 0);

        // No need to sync among other threads here
        keymix_inner(thr->ctx, thr->in, thr->out, thr->chunk_size, iv, counter,
                     thr->unsync_levels);
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
                .level           = thr->unsync_levels,
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
                spread_opt(&args); // always called with at least 1 level

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

int keymix_iv_counter(ctx_t *ctx, byte *in, byte *out, size_t size, byte* iv,
                      uint32_t counter, uint8_t nof_threads) {
        uint64_t tot_macros;
        uint64_t macros;
        uint8_t levels;
        uint8_t unsync_levels;
        size_t thread_chunk_size;
        byte *offset;

        tot_macros = size / ctx->block_size;
        _log(LOG_DEBUG, "total macros:\t%d\n", tot_macros);
        levels = get_levels(size, ctx->block_size, ctx->fanout);
        _log(LOG_DEBUG, "total levels:\t%d\n", levels);

        // Ensure 1 <= #threads <= #macros
        nof_threads = MAX(1, MIN(nof_threads, tot_macros));
        _log(LOG_DEBUG, "#threads:\t%d\n", nof_threads);

        // If there is 1 thread, just use the function directly, no need to
        // allocate and deallocate a lot of stuff
        if (nof_threads == 1) {
                if (ctx->enc_mode != ENC_MODE_CTR_OPT) {
                        keymix_inner(ctx, in, out, size, iv, counter, levels);
                } else {
                        keymix_inner_opt(ctx, in, out, size, iv, counter, levels);
                }
                return 0;
        }

        // If the #threads divides the #macros and #macros per thread is a
        // multiple of a fanout power, the threads won't write in other threads
        // memory up to the level exceeding that fanout power. So the threads
        // can initially run without syncronization and only then be
        // syncronized on the last few levels
        // NOTE: The 1st layer of encryption can always be done unsyncronized
        unsync_levels = 1;
        if (tot_macros % nof_threads == 0) {
                thread_chunk_size = tot_macros / nof_threads;
                macros = 1;
                unsync_levels = 0;
                while (thread_chunk_size % macros == 0) {
                        macros *= ctx->fanout;
                        unsync_levels += 1;
                }
        }
        _log(LOG_DEBUG, "unsync levels:\t%d\n", unsync_levels);

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

                a->id            = t;
                a->nof_threads   = nof_threads;
                a->barrier       = &barrier;
                a->ctx           = ctx;
                a->in            = in;
                a->abs_out       = out;
                a->out           = offset;
                a->chunk_size    = thread_chunk_size;
                a->total_size    = size;
                a->unsync_levels = unsync_levels;
                a->total_levels  = levels;
                a->iv            = iv;
                a->counter       = counter;

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

int keymix(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t nof_threads) {
        return keymix_iv_counter(ctx, in, out, size, NULL, 0, nof_threads);
}
