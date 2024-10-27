#include "spread.h"

#include <assert.h>

#include "log.h"
#include "mix.h"
#include "utils.h"

// Spread the output of the encryption owned by the current thread to the
// following threads belonging to the same slab. The operation despite being
// done inplace is thread-safe since there is no overlap between the read and
// write operations of the threads.
void spread(spread_args_t *args) {
        uint64_t tot_macros;
        uint64_t offset;
        bool extra_macro;
        uint64_t macros;
        uint64_t prev_slab_macros;
        uint64_t curr_slab_macros;
        uint8_t prev_slab;
        block_size_t mini_size;
        byte *base;
        byte *from;
        byte *to;

        tot_macros = args->buffer_abs_size / args->block_size;

        // Current thread offset
        offset = (args->buffer - args->buffer_abs) / args->block_size;

        // Current thread window size
        extra_macro = (args->thread_id < tot_macros % args->nof_threads);
        macros = tot_macros / args->nof_threads + extra_macro;

        _log(LOG_DEBUG, "[t=%d] tot_macros = %ld, offset = %ld, macros = %ld\n",
             args->thread_id, tot_macros, offset, macros);

        assert(args->level >= 1);
        prev_slab_macros = intpow(args->fanout, args->level - 1);
        mini_size = args->block_size / args->fanout;

        for (uint64_t macro = offset; macro < offset + macros; macro++) {
                // Previous slab of the current macro
                prev_slab = (macro / prev_slab_macros) % args->fanout;
                _log(LOG_DEBUG, "[t=%d] macro = %ld, prev_slab = %d\n", args->thread_id, macro, prev_slab);

                for (uint8_t mini = prev_slab + 1; mini < args->fanout; mini++) {
                        base = args->buffer_abs + args->block_size * macro;
                        from = base + mini_size * mini;
                        to = base + args->block_size * prev_slab_macros * (mini - prev_slab) + mini_size * prev_slab;

                        _log(LOG_DEBUG, "[t=%d] mini = %d, from = %ld, to = %ld\n",
                             args->thread_id, mini, macro * args->fanout + mini,
                             (macro + prev_slab_macros * (mini - prev_slab)) * args->fanout + prev_slab);

                        memswap(from, to, mini_size);
                }
        }
}

void spread_opt(spread_args_t *args) {
        block_size_t block_size;
        uint64_t tot_macros;
        uint64_t offset;
        bool extra_macro;
        uint64_t macros;
        uint64_t end;
        uint8_t fanout;
        uint64_t prev_slab_macros;
        uint64_t curr_slab_macros;
        size_t prev_slab_size;
        block_size_t mini_size;
        uint64_t prev_slabs;
        uint8_t prev_slab;
        uint64_t curr_macros;
        byte *buffer;
        byte *base;
        byte *from;
        byte *to;

        buffer = args->buffer_abs;
        block_size = args->block_size;
        tot_macros = args->buffer_abs_size / block_size;

        // Thread window start
        offset = (args->buffer - buffer) / block_size;
        // Thread window size
        extra_macro = (args->thread_id < tot_macros % args->nof_threads);
        macros = tot_macros / args->nof_threads + extra_macro;
        // Thread window end
        end = offset + macros;

        // _log(LOG_DEBUG, "[t=%d] tot_macros = %ld, offset = %ld, macros = %ld\n",
        //      args->thread_id, tot_macros, offset, macros);

        assert(args->level >= 1);
        fanout = args->fanout;
        prev_slab_macros = intpow(fanout, args->level - 1);
        prev_slab_size = block_size * prev_slab_macros;
        mini_size = block_size / fanout;

        // To improve performance, we need to know how many previous slabs we
        // process, the one we are in and its number of macros
        prev_slabs = ceil((double) end / prev_slab_macros) - offset / prev_slab_macros;
        prev_slab = (offset / prev_slab_macros) % fanout;

        // _log(LOG_DEBUG, "[t=%d] prev_slab_macros = %ld, prev_slabs = %ld, prev_slab = %ld\n",
        //      args->thread_id, prev_slab_macros, prev_slabs, prev_slab);

        // Iterate over all prev slabs
        for (uint64_t i = 0; i < prev_slabs; i++) {
                // Number of macros to process in the current previous slab
                curr_macros = prev_slab_macros;
                if (!i && prev_slabs == 1) {
                        // Window smaller than the previous slab size
                        curr_macros = macros;
                } else if (!i) {
                        // Not aligned first previous slab
                        curr_macros = prev_slab_macros - offset % prev_slab_macros;
                } else if (i == prev_slabs - 1 && end % prev_slab_macros) {
                        // Not aligned last previous slab
                        curr_macros = end % prev_slab_macros;
                }

                // Swaps are always done ahead (i.e. to > from), so the last
                // previous slab is subject to changes from all previous slabs
                // and has nothing to do
                if (prev_slab == fanout - 1) {
                        prev_slab = (prev_slab + 1) % fanout;
                        offset += curr_macros;
                        continue;
                }

                // Iterate over all macros part of the window in the current prev slab
                for (uint64_t macro = offset; macro < offset + curr_macros; macro++) {
                        // _log(LOG_DEBUG, "[t=%d] curr_macros = %ld, macro = %ld, prev_slab = %d\n",
                        //      args->thread_id, curr_macros, macro, prev_slab);

                        for (uint8_t mini = prev_slab + 1; mini < fanout; mini++) {
                                base = buffer + block_size * macro;
                                from = base + mini_size * mini;
                                to = base + block_size * prev_slab_macros * (mini - prev_slab) + mini_size * prev_slab;

                                // _log(LOG_DEBUG, "[t=%d] mini = %d, from = %ld, to = %ld\n",
                                //      args->thread_id, mini, macro * fanout + mini,
                                //      (macro + prev_slab_macros * (mini - prev_slab)) * fanout + prev_slab);

                                memswap(from, to, mini_size);
                        }
                }

                prev_slab = (prev_slab + 1) % fanout;
                offset += curr_macros;
        }
}
