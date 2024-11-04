#include "keymix.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "barrier.h"
#include "ctx.h"
#include "config.h"
#include "log.h"
#include "spread.h"
#include "types.h"
#include "utils.h"

// --------------------------------------------------------- Types for threading

typedef struct {
        uint8_t id;
        uint8_t nof_threads;
        thr_barrier_t *barrier;
        ctx_t *ctx;
        byte *in;
        byte *out;
        byte *abs_in;
        byte *abs_out;
        size_t chunk_size;
        size_t total_size;
        uint8_t unsync_levels;
        uint8_t total_levels;
        byte *iv;
        uint64_t counter;
} thr_keymix_t;

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

inline void _reverse64bits(uint64_t *x) {
        byte *data  = (byte *)x;
        size_t size = sizeof(*x);
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define __correct_endianness(...) _reverse64bits(__VA_ARGS_)
#else
#define __correct_endianness(...)
#endif

// Copy 1st block size of the key and update its 1st 128 bits as follows:
// - XOR IV with 1st 64 bits of the key
// - Sum counter to the following 64 bits of the key
// Then, encrypt the 1st block size, this is done to preserve the key and avoid
// allocating extra memory
void update_iv_counter_block(mix_func_t mixpass, byte *in, byte *out,
                             block_size_t block_size, byte *iv,
                             uint64_t counter) {
        byte block[block_size];
        uint64_t *counter_ptr;

        memcpy(block, in, block_size);
        memxor(block, block, iv, KEYMIX_NONCE_SIZE);
        counter_ptr = (uint64_t *)(block + KEYMIX_NONCE_SIZE);
        __correct_endianness(counter_ptr);
        (*counter_ptr) += counter;
        __correct_endianness(counter_ptr);
        (*mixpass)(block, out, block_size, MIXPASS_DEFAULT_IV);
}

void keymix_inner(ctx_t *ctx, byte* in, byte* out, size_t size, byte* iv,
                  uint64_t counter, uint8_t levels, uint8_t tot_levels) {
        mix_func_t mixpass = ctx->mixpass;
        byte *out_first    = out;
        size_t size_first  = size;
        byte *mixpass_iv   = MIXPASS_DEFAULT_IV;

        // If the enc mode is ctr/ctr-opt and a one-way mixing function is
        // specified, we do a one-way pass at the last level
        bool do_one_way_mixpass = (ctx->enc_mode != ENC_MODE_OFB &&
                                   ctx->one_way_mix != NONE);

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

        if (do_one_way_mixpass && tot_levels == 1) {
                mixpass = ctx->one_way_mixpass;
        }

        if (iv) {
                if (ctx->enc_mode != ENC_MODE_OFB) {
                        // Update 1st block with IV and counter on its own
                        update_iv_counter_block(mixpass, in, out,
                                                ctx->block_size, iv, counter);

                        // Skip 1st block with 1st encryption level
                        in += ctx->block_size;
                        out_first += ctx->block_size;
                        size_first -= ctx->block_size;
                } else {
                        // No changes to blocks
                        out_first = out;
                        size_first = size;

                        // But use user provided IV for the mixpass
                        mixpass_iv = iv;
                }
        }

        (*mixpass)(in, out_first, size_first, mixpass_iv);
        for (args.level = 1; args.level < levels; args.level++) {
                spread_opt(&args);
                if (do_one_way_mixpass && args.level == tot_levels - 1) {
                        mixpass = ctx->one_way_mixpass;
                }
                (*mixpass)(out, out, size, mixpass_iv);
        }
}

// The input of the optimized version is not the key itself, but the result of
// its precomputation.
// When the operation is requested inplace (i.e., in == out), we overwrite the
// state, so we expect copies of the original state have been made by the
// caller. On the other hand, when they are not inplace the input shall not be
// be changed.
void keymix_inner_opt(ctx_t *ctx, byte* in, byte* out, size_t size, byte* iv,
                      uint64_t counter, uint8_t levels, uint8_t tot_levels) {
        size_t curr_size   = ctx->block_size;
        mix_func_t mixpass = ctx->mixpass;

        // If the enc mode is ctr/ctr-opt and a one-way mixing function is
        // specified, we do a one-way pass at the last level
        bool do_one_way_mixpass = (ctx->one_way_mix != NONE);

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

        if (do_one_way_mixpass && tot_levels == 1) {
                mixpass = ctx->one_way_mixpass;
        }

        // 1st level
        if (iv) {
                // Update 1st block with IV and counter on its own
                update_iv_counter_block(mixpass, in, out, ctx->block_size, iv,
                                        counter);
        } else {
                // Encrypt 1st block as is
                (*mixpass)(in, out, curr_size, MIXPASS_DEFAULT_IV);
        }

        // Other levels
        for (args.level = 1; args.level < levels; args.level++) {
                curr_size *= ctx->fanout;
                args.buffer_abs_size = curr_size;
                args.buffer_size     = curr_size;
                spread_opt(&args);

                if (do_one_way_mixpass && args.level == tot_levels - 1) {
                        mixpass = ctx->one_way_mixpass;
                }

                (*mixpass)(out, out, curr_size, MIXPASS_DEFAULT_IV);
        }
}

// --------------------------------------------------------- Multi-threaded keymix

int sync_spread_and_mixpass(thr_keymix_t *thr, spread_args_t *args) {
        ctx_t *ctx         = thr->ctx;
        mix_func_t mixpass = ctx->mixpass;
        byte *mixpass_iv   = MIXPASS_DEFAULT_IV;

        // When using ofb encryption mode and the user provides an IV pass it
        // down to the mixpass
        if (ctx->enc_mode == ENC_MODE_OFB && thr->iv) {
                mixpass_iv = thr->iv;
        }

        // Wait for all threads to finish the encryption step
        int err = barrier(thr->barrier, thr->nof_threads);
        if (err) {
                _log(LOG_ERROR, "t=%d: barrier error %d\n", thr->id, err);
                return 1;
        }

        _log(LOG_DEBUG, "t=%d: sychronized swap (level %d)\n", thr->id,
             args->level - 1);
        spread_opt(args);

        // Wait for all threads to finish the swap step
        err = barrier(thr->barrier, thr->nof_threads);
        if (err) {
                _log(LOG_ERROR, "t=%d: barrier error %d\n", thr->id, err);
                return 1;
        }

        _log(LOG_DEBUG, "t=%d: sychronized encryption (level %d)\n", thr->id,
             args->level);
        // If the enc mode is ctr/ctr-opt, a one-way mixing function is
        // specified, and the current level is the last one, we do a one-way
        // pass
        if (ctx->enc_mode != ENC_MODE_OFB && ctx->one_way_mix != NONE &&
            args->level == thr->total_levels - 1) {
                mixpass = ctx->one_way_mixpass;
        }
        err = (*(mixpass))(args->buffer, args->buffer, args->buffer_size,
                           mixpass_iv);
        if (err) {
                _log(LOG_ERROR, "t=%d: mixpass error %d\n", thr->id, err);
                return 1;
        }

        return 0;
}

void *w_thread_keymix(void *a) {
        thr_keymix_t *thr     = (thr_keymix_t *)a;
        ctx_t *ctx            = thr->ctx;
        byte *iv              = (!thr->id ? thr->iv : NULL);
        uint64_t counter      = (!thr->id ? thr->counter : 0);

        // When using ofb encryption mode give the IV to all threads, so they
        // can pass it down to the mixpass
        if (ctx->enc_mode == ENC_MODE_OFB) {
                iv = thr->iv;
        }

        // No need to sync among other threads here
        keymix_inner(thr->ctx, thr->in, thr->out, thr->chunk_size, iv, counter,
                     thr->unsync_levels, thr->total_levels);
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
                int err = sync_spread_and_mixpass(thr, &args);
                if (err) {
                        _log(LOG_ERROR, "t=%d: syncronization error (level %d)\n",
                             args.level);
                        goto thread_exit;
                }
        }

thread_exit:
        return NULL;
}

// The input of the optimized version is not the key itself, but the result of
// its precomputation.
// When the operation is requested inplace (i.e., in == out), we overwrite the
// state, so we expect copies of the original state have been made by the
// caller. On the other hand, when they are not inplace the input shall not be
// be changed.
void *w_thread_keymix_opt(void *a) {
        uint64_t other_macros;
        uint64_t offset;
        uint64_t macros;
        uint64_t curr_tot_macros;

        thr_keymix_t *thr = (thr_keymix_t *)a;
        ctx_t *ctx        = thr->ctx;
        byte *iv          = (!thr->id ? thr->iv : NULL);
        uint64_t counter  = (!thr->id ? thr->counter : 0);

        size_t curr_tot_size = thr->chunk_size;

        // No need for syncronization in the 1st layers

        if (!thr->id) {
                // At the beginning only the 1st thread performs the keymix
                // up to a predetermined number of levels
                keymix_inner_opt(thr->ctx, thr->abs_in, thr->abs_out,
                                 curr_tot_size, iv, counter,
                                 thr->unsync_levels, thr->total_levels);
                _log(LOG_DEBUG, "t=%d: finished mixing prefix of internal state\n",
                     thr->id);
        } else if (thr->abs_in != thr->abs_out) {
                // Other threads copy the remaining part of the internal state
                // to the output buffer so that we are ready to perform the
                // following levels

                // #macros not part of the mixing done by the 1st thread
                other_macros = (thr->total_size - curr_tot_size) / ctx->block_size;
                // Thread window start
                offset = get_curr_thread_offset(other_macros, thr->id - 1,
                                                thr->nof_threads - 1);
                // Thread window size
                macros = get_curr_thread_size(other_macros, thr->id - 1,
                                              thr->nof_threads - 1);

                memcpy(thr->abs_out + curr_tot_size + ctx->block_size * offset,
                       thr->abs_in + curr_tot_size + ctx->block_size * offset,
                       ctx->block_size * macros);

                _log(LOG_DEBUG, "t=%d: finished copying the internal state\n",
                     thr->id);
        }

        _log(LOG_DEBUG, "t=%d: finished layers without coordination\n", thr->id);

        // Synchronized layers

        spread_args_t args = {
                .thread_id   = thr->id,
                .nof_threads = thr->nof_threads,
                .buffer_abs  = thr->abs_out,
                .fanout      = ctx->fanout,
                .block_size  = ctx->block_size,
                .level       = thr->unsync_levels,
        };

        for (; args.level < thr->total_levels; args.level++) {
                curr_tot_size *= ctx->fanout;

                // #macros to mix at the current level
                curr_tot_macros = curr_tot_size / ctx->block_size;
                // Thread window start
                offset = get_curr_thread_offset(curr_tot_macros, thr->id,
                                                thr->nof_threads);
                // Thread window size
                macros = get_curr_thread_size(curr_tot_macros, thr->id,
                                              thr->nof_threads);

                // Update spread args accoring to the thread id and the current
                // size
                args.buffer          = thr->abs_out + ctx->block_size * offset;
                args.buffer_abs_size = curr_tot_size;
                args.buffer_size     = ctx->block_size * macros;

                int err = sync_spread_and_mixpass(thr, &args);
                if (err) {
                        _log(LOG_ERROR, "t=%d: syncronization error (level %d)\n",
                             args.level);
                        goto thread_exit;
                }
        }

thread_exit:
        return NULL;
}

int keymix_iv_counter(ctx_t *ctx, byte *in, byte *out, size_t size, byte* iv,
                      uint64_t counter, uint8_t nof_threads) {
        uint64_t tot_macros;
        uint64_t macros;
        uint8_t levels;
        uint8_t unsync_levels;
        size_t thread_chunk_size;
        byte *in_offset;
        byte *out_offset;

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
                        keymix_inner(ctx, in, out, size, iv, counter, levels,
                                     levels);
                } else {
                        keymix_inner_opt(ctx, in, out, size, iv, counter, levels,
                                         levels);
                }
                return 0;
        }

        if (ctx->enc_mode != ENC_MODE_CTR_OPT) {
                // If the #threads divides the #macros and #macros per thread
                // is a multiple of a fanout power, the threads won't write in
                // other threads memory up to the level exceeding that fanout
                // power. So the threads can initially run without
                // syncronization and only then be syncronized on the last few
                // levels
                // NOTE: The 1st layer of encryption can always be done
                // unsyncronized
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
        } else {
                // The optimized version initially runs entirely within the 1st
                // thread, only then once we have enough blocks to process the
                // computation can be shared with the entire pull of threads

                // Set the size and #levels done by the 1st thread based on the
                // #threads available.
                macros = 1;
                unsync_levels = 0;
                while (macros <= nof_threads) {
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

        in_offset = in;
        out_offset = out;

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_keymix_t *a = args + t;

                if (ctx->enc_mode != ENC_MODE_CTR_OPT) {
                        // #macros done by the current thread
                        macros = get_curr_thread_size(tot_macros, t, nof_threads);
                        thread_chunk_size = ctx->block_size * macros;
                } else {
                        // #macros done by the 1st thread
                        macros = intpow(ctx->fanout, unsync_levels - 1);
                        thread_chunk_size = ctx->block_size * macros;
                }

                a->id            = t;
                a->nof_threads   = nof_threads;
                a->barrier       = &barrier;
                a->ctx           = ctx;
                a->abs_in        = in;
                a->in            = in_offset;
                a->abs_out       = out;
                a->out           = out_offset;
                a->chunk_size    = thread_chunk_size;
                a->total_size    = size;
                a->unsync_levels = unsync_levels;
                a->total_levels  = levels;
                a->iv            = iv;
                a->counter       = counter;

                if (ctx->enc_mode != ENC_MODE_CTR_OPT) {
                        pthread_create(&threads[t], NULL, w_thread_keymix, a);
                } else {
                        pthread_create(&threads[t], NULL, w_thread_keymix_opt, a);
                }

                in_offset += thread_chunk_size;
                out_offset += thread_chunk_size;
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

int keymix_iv(ctx_t *ctx, byte *in, byte *out, size_t size, byte *iv,
              uint8_t nof_threads) {
        return keymix_iv_counter(ctx, in, out, size, iv, 0, nof_threads);
}

int keymix(ctx_t *ctx, byte *in, byte *out, size_t size, uint8_t nof_threads) {
        return keymix_iv_counter(ctx, in, out, size, NULL, 0, nof_threads);
}
