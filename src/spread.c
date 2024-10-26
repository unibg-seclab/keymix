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
