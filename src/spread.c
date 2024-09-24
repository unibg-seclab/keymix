#include "spread.h"

#include "utils.h"
#include <assert.h>

// This function spreads the output of the encryption produced by
// the single thread across multiple slabs inplace.
void spread(byte *buffer, size_t size, uint8_t level, uint8_t fanout, size_t size_macro) {
        if (DEBUG) {
                assert(level > 0);
        }

        byte *in  = buffer;
        byte *out = buffer;

        size_t mini_size = size_macro / fanout;

        uint64_t prev_macros_in_slab = intpow(fanout, level - 1);
        uint64_t macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * size_macro;
        size_t slab_size             = macros_in_slab * size_macro;

        byte *last = out + size;
        uint64_t in_mini_offset, out_macro_offset, out_mini_offset;

        while (out < last) {
                // With inplace swap we never have to look back on the previous
                // slab parts. Moreover, when we get to the last slab part we
                // have nothing to do, previous swap operations have already
                // managed to set this last slab part right.
                in_mini_offset = 0;
                for (uint8_t prev_slab = 0; prev_slab < fanout - 1; prev_slab++) {
                        out_macro_offset = 0;
                        for (uint64_t macro = 0; macro < prev_macros_in_slab; macro++) {
                                in_mini_offset += (prev_slab + 1) * mini_size;
                                out_mini_offset =
                                    (prev_slab + 1) * prev_slab_size + prev_slab * mini_size;
                                for (uint8_t mini = prev_slab + 1; mini < fanout; mini++) {
                                        memswap(out + out_macro_offset + out_mini_offset,
                                                in + in_mini_offset, mini_size);
                                        in_mini_offset += mini_size;
                                        out_mini_offset += prev_slab_size;
                                }
                                out_macro_offset += size_macro;
                        }
                }
                in += slab_size;
                out += slab_size;
        }
}

// Spread the output of the encryption owned by the current thread to the
// following threads belonging to the same slab. The operation despite being
// done inplace is thread-safe since there is no overlap between the read and
// write operations of the threads.
//
// Note, this is using a different mixing behavior with respect to the Mix&Slice
// shuffle.
void spread_chunks(spread_chunks_args_t *args) {
        if (DEBUG)
                assert(args->level >= args->thread_levels);

        size_t mini_size = args->size_macro / args->fanout;

        uint64_t prev_macros_in_slab = intpow(args->fanout, args->level - 1);
        uint64_t macros_in_slab      = args->fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * args->size_macro;
        size_t slab_size             = macros_in_slab * args->size_macro;

        uint8_t nof_threads = intpow(args->fanout, args->total_levels - args->thread_levels);
        uint64_t nof_slabs  = args->buffer_abs_size / slab_size;
        uint8_t nof_threads_per_slab      = nof_threads / nof_slabs;
        uint8_t prev_nof_threads_per_slab = nof_threads_per_slab / args->fanout;

        uint8_t prev_slab;
        if (prev_nof_threads_per_slab <= 1) {
                prev_slab = args->thread_id % args->fanout;
        } else {
                prev_slab = (args->thread_id % nof_threads_per_slab) / prev_nof_threads_per_slab;
        }

        // Don't do anything if the current thread belongs to the last
        // prev_slab.
        // Note, this inevitably reduces the amount of parallelism we can
        // accomplish.
        if (prev_slab == args->fanout - 1) {
                return;
        }

        uint64_t out_slab_offset        = slab_size * (args->thread_id / nof_threads_per_slab);
        uint64_t out_inside_slab_offset = 0;
        if (prev_nof_threads_per_slab > 1) {
                out_inside_slab_offset =
                    args->buffer_size * (args->thread_id % prev_nof_threads_per_slab);
        }
        uint64_t out_mini_offset = prev_slab * mini_size;

        byte *in  = args->buffer;
        byte *out = args->buffer_abs + out_slab_offset + out_inside_slab_offset + out_mini_offset;

        uint64_t nof_macros = args->buffer_size / args->size_macro;

        uint64_t in_mini_offset   = 0;
        uint64_t out_macro_offset = 0;

        for (uint64_t macro = 0; macro < nof_macros; macro++) {
                // Note, differently from the 'normal' implementation of the
                // spread_chunks, here we do not look back on previous parts of
                // the slab. Indeed, previous threads take care of them.
                in_mini_offset += (prev_slab + 1) * mini_size;
                out_mini_offset = (prev_slab + 1) * prev_slab_size; // + prev_slab * mini_size;
                for (uint8_t mini = prev_slab + 1; mini < args->fanout; mini++) {
                        memswap(out + out_macro_offset + out_mini_offset, in + in_mini_offset,
                                mini_size);
                        in_mini_offset += mini_size;
                        out_mini_offset += prev_slab_size;
                }
                out_macro_offset += args->size_macro;
        }
}
