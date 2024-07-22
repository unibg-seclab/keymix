#include "utils.h"
#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

void _log(log_level_t level, const char *fmt, ...) {
        if (!DISABLE_LOG && level >= LOG_LEVEL) {
                va_list args;
                va_start(args, fmt);
                vfprintf(stderr, fmt, args);
                va_end(args);
        }
}

inline double MiB(double size) { return size / 1024 / 1024; }

inline size_t intpow(size_t base, size_t exp) {
        size_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

// If we interpret in and out a series of mini_blocks, each single one
// of size SIZE_MACRO / fanout, then the formula to shuffle them is actually quite simple
//
// Consider the first (fanout ^ level) macro-blocks
//    for each j in the indexes of the out part in this frist macro-blocks
//        i = (fanout ^ level) * (j % fanout) + floor(j / fanout)
//        out[j] = in[j]
// And then repeat for the remaining, with the approriate offset.
//
// This is the slow version, with the formula as close to the original as
// possible and clearly visible in the inner for. See `shuffle_opt` for a full
// optimization on how we calculate the values.
//
// Example:
// size = 4 * SIZE_MACRO, fanout = 2
// in  = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7
// out = 0 | 4 | 1 | 5 | 2 | 6 | 3 | 7
void shuffle(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
             unsigned int fanout) {
        if (DEBUG)
                assert(level > 0);
        size_t mini_size      = SIZE_MACRO / fanout;
        byte *last            = out + in_size;
        size_t macros_in_slab = intpow(fanout, level);
        size_t slab_size      = macros_in_slab * SIZE_MACRO;

        _log(LOG_DEBUG, "Moving pieces of %zu B\n", mini_size);
        _log(LOG_DEBUG, "Over a total of %zu slabs\n", in_size / slab_size);

        for (; out < last; out += slab_size, in += slab_size) {
                _log(LOG_DEBUG, "New slab\n");

                for (size_t j = 0; j < (slab_size / mini_size); j++) {
                        size_t i = macros_in_slab * (j % fanout) + j / fanout;
                        _log(LOG_DEBUG, "%zu -> %zu\n", i, j);
                        memcpy(out + j * mini_size, in + i * mini_size, mini_size);
                }
        }
}

// This is the same as the previous one, but trying to optimize the stuff
// Look further for a better optimization of this
//
// Here we want to have indexes from 0 to (slab_size / mini_size)
// That is, from 0 to
// (macros_in_slab * SIZE_MACRO) / (SIZE_MACRO / fanout)
//    = macros_in_slab * fanout
//    = fanout ^ (level+1)
//
// E.g., with fanout = 3, we want 0,1,2,...,8 (a total of 3^2 = 9 indices)
// for level = 1
// This means we can use 2 for
//  - One external with k = 0,...,fanout^level - 1 (= 0,...,macros_in_slab-1)
//  - One internal with n = 0,...,fanout-1 (which we can call mod)
// And we get that
//  k = j / fanout
//  mod = j % fanout
void shuffle_opt(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
                 unsigned int fanout) {
        if (DEBUG)
                assert(level > 0);

        size_t mini_size      = SIZE_MACRO / fanout;
        byte *last            = out + in_size;
        size_t macros_in_slab = intpow(fanout, level);
        size_t slab_size      = macros_in_slab * SIZE_MACRO;

        size_t i           = 0;
        size_t i_increment = mini_size * macros_in_slab;

        while (out < last) {
                for (size_t k = 0; k < macros_in_slab; k++) {
                        // This is split around, but essentialy
                        // calculates
                        //        size_t i = macros_in_slab * mod + k;
                        // for mod and k starting both from 0
                        // We reset i to mini_size * k every time k changes,
                        // and increment it by mini_size * macros_in_slab
                        // for every mod. In this way, we use less multiplications.
                        i = mini_size * k;
                        for (size_t mod = 0; mod < fanout; mod++) {
                                memcpy(out, in + i, mini_size);
                                i += i_increment;
                                out += mini_size;
                        }
                }
                in += slab_size;
        }
}

// This follows the same schema of the shuffle, but does not assume access to
// the entire input to shuffle (e.g., because the entire input is produced
// across a pull of threads). On the other hand, this function spreads the
// output of the encryption produced by the single thread across multiple
// slabs.
// Note that we use the "other viewpoint" of the formula used in shuffle.
// If we consider i to be the index of a mini-block in a slab of the input,
// and j to be the same thing for the output, then the rules that link these
// two are
//
//      i = fanout^level * (j % fanout) + j / fanout
//      j = fanout * (i % (fanout^level)) + j / (fanout^level)
//
// Note that fanout^level = macros_in_slab
void shuffle_chunks(thread_data *args, int level) {
        unsigned int fanout = args->mixconfig->diff_factor;

        size_t mini_size         = SIZE_MACRO / fanout;
        unsigned long nof_macros = args->thread_chunk_size / SIZE_MACRO;

        unsigned long macros_in_slab = intpow(fanout, level);
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

        byte *in  = args->out;
        byte *out = args->abs_buf;

        byte *in_abs = args->abs_out;

        unsigned long in_offset = 0;
        unsigned long src_abs, src_rel, dst_abs, dst_rel;

        for (unsigned long macro = 0; macro < nof_macros; macro++) {
                for (unsigned int mini = 0; mini < fanout; mini++) {
                        src_abs = (args->thread_chunk_size * args->thread_id) / mini_size +
                                  fanout * macro + mini;
                        // Alternative
                        // src_abs = (in - in_abs) / mini_size + fanout * macro + mini;
                        src_rel = src_abs % (fanout * macros_in_slab);
                        dst_rel = fanout * (src_rel % macros_in_slab) + src_rel / macros_in_slab;
                        dst_abs = (src_abs - src_rel) + dst_rel;
                        memcpy(out + dst_abs * mini_size, in + in_offset, mini_size);
                        in_offset += mini_size;
                }
        }
}

// Same as before, but trying to optimize the calculations with the same
// ideas as for shuffle_opt
void shuffle_chunks_opt(thread_data *args, int level) {
        unsigned int fanout = args->mixconfig->diff_factor;

        size_t mini_size             = SIZE_MACRO / fanout;
        unsigned long macros_in_slab = intpow(fanout, level);
        unsigned long minis_in_slab  = fanout * macros_in_slab;

        byte *in      = args->out;
        byte *in_abs  = args->abs_out;
        byte *last    = in + args->thread_chunk_size;
        byte *out_abs = args->abs_buf;

        unsigned long minis_from_origin = (in - in_abs) / mini_size;
        unsigned long src               = minis_from_origin % minis_in_slab;

        while (in < last) {
                unsigned long dst = fanout * (src % macros_in_slab) + src / macros_in_slab;
                memcpy(out_abs + dst * mini_size, in, mini_size);

                in += mini_size;
                src++;
        }
}

void swap(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
          unsigned int diff_factor) {
        if (DEBUG)
                assert(level > 0);

        int size_block = SIZE_MACRO / diff_factor;

        // divide the input into slabs based on the diff_factor
        unsigned long prev_slab_blocks = intpow(diff_factor, level);
        size_t slab_size               = prev_slab_blocks * diff_factor * size_block;
        unsigned long nof_slabs        = in_size / slab_size;
        size_t prev_slab_size          = size_block * prev_slab_blocks;

        _log(LOG_DEBUG,
             "swap, level %d, diff_factor %d, prev_slab_blocks %ld, slab_size "
             "%ld, in_size %ld\n",
             level, diff_factor, prev_slab_blocks, slab_size, in_size);

        size_t offset_slab      = 0;
        size_t offset_prev_slab = 0;
        size_t offset_out       = 0;
        size_t offset_psb       = 0;
        for (; nof_slabs > 0; nof_slabs--) {
                offset_prev_slab = offset_slab;
                for (unsigned int di = 0; di < diff_factor; di++) {
                        offset_psb = 0;
                        offset_out = offset_slab + di * size_block;
                        for (unsigned long psb = 0; psb < prev_slab_blocks; psb++) {
                                memcpy(out + offset_out, in + offset_prev_slab + offset_psb,
                                       size_block);
                                offset_out += SIZE_MACRO;
                                offset_psb += size_block;
                        }
                        offset_prev_slab += prev_slab_size;
                }
                offset_slab += slab_size;
        }
}

// DOES NOT WORK!!!
void swap_chunks(thread_data *args, int level) {
        int size_block = SIZE_MACRO / args->mixconfig->diff_factor;

        size_t prev_slab_size = size_block;
        for (unsigned int i = 0; i < level; i++) {
                prev_slab_size *= args->mixconfig->diff_factor;
        }
        size_t slab_size              = args->mixconfig->diff_factor * prev_slab_size;
        unsigned long chunk_blocks    = args->thread_chunk_size / size_block;
        unsigned long chunk_start_pos = args->thread_id * args->thread_chunk_size;
        unsigned long slab_start_pos  = chunk_start_pos - chunk_start_pos % slab_size;
        unsigned long UPFRONT_BLOCKS_OFFSET =
            args->mixconfig->diff_factor * (chunk_start_pos % prev_slab_size);

        size_t OFFSET = slab_start_pos + UPFRONT_BLOCKS_OFFSET;

        _log(LOG_DEBUG,
             "swap, level %d, thread_id %d, diff_factor %d, thread_id %d, "
             "PREV_SLAB_SIZE %ld, "
             "SIZE_SLAB %ld, "
             "chunk_size %ld, OFFSET %ld\n",
             level, args->thread_id, args->mixconfig->diff_factor, args->thread_id, prev_slab_size,
             slab_size, args->thread_chunk_size, OFFSET);

        for (unsigned long block = 0; block < chunk_blocks; block++) {
                memcpy(args->abs_buf + OFFSET, args->out + block * size_block, size_block);
                OFFSET += SIZE_MACRO;
        }
}

// This mixing function assumes access to the entire input to shuffle. On the
// other hand, this function spreads the output of the encryption produced by
// the single thread across multiple slabs.
//
// This is using a different mixing behavior with respect to the shuffle and
// swap functions above.
//
// Note: despite the function could be executed inplace we are not doing it
// here.
//
// Example:
// size = 4 * SIZE_MACRO, fanout = 2
// in  = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7
// out = 0 | 4 | 2 | 6 | 1 | 5 | 3 | 7
void spread(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
            unsigned int fanout) {
        if (DEBUG)
                assert(level > 0);

        size_t mini_size = SIZE_MACRO / fanout;

        unsigned long prev_macros_in_slab = intpow(fanout, level - 1);
        unsigned long macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size             = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size                  = macros_in_slab * SIZE_MACRO;

        byte *last              = out + in_size;
        unsigned long in_offset = 0;
        unsigned long out_macro_offset, out_mini_offset;

        while (out < last) {
                for (unsigned int prev_slab = 0; prev_slab < fanout; prev_slab++) {
                        out_macro_offset = 0;
                        for (unsigned long macro = 0; macro < prev_macros_in_slab; macro++) {
                                out_mini_offset = prev_slab * mini_size;
                                for (unsigned int mini = 0; mini < fanout; mini++) {
                                        memcpy(out + out_macro_offset + out_mini_offset,
                                               in + in_offset, mini_size);
                                        in_offset += mini_size;
                                        out_mini_offset += prev_slab_size;
                                }
                                out_macro_offset += SIZE_MACRO;
                        }
                }
                out += slab_size;
        }
}

void memswap(byte *a, byte *b, size_t bytes) {
        byte *a_end = a + bytes;
        while (a < a_end) {
                char tmp = *a;
                *a++     = *b;
                *b++     = tmp;
        }
}

// This function spreads the output of the encryption produced by
// the single thread across multiple slabs inplace.
void spread_inplace(byte *restrict buffer, size_t in_size, unsigned int level,
                    unsigned int fanout) {
        if (DEBUG) {
                assert(level > 0);
        }

        byte *in  = buffer;
        byte *out = buffer;

        size_t mini_size = SIZE_MACRO / fanout;

        unsigned long prev_macros_in_slab = intpow(fanout, level - 1);
        unsigned long macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size             = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size                  = macros_in_slab * SIZE_MACRO;

        byte *last                   = out + in_size;
        unsigned long in_mini_offset = 0;
        unsigned long out_macro_offset, out_mini_offset;

        while (out < last) {
                for (unsigned int prev_slab = 0; prev_slab < fanout - 1; prev_slab++) {
                        out_macro_offset = 0;
                        for (unsigned long macro = 0; macro < prev_macros_in_slab; macro++) {
                                // With inplace swap we never have to look back on the previous
                                // slab parts. Moreover, when we get to the last slab part we
                                // have nothing to do, previous swap operations have already
                                // managed to set this last slab part right.

                                in_mini_offset += (prev_slab + 1) * mini_size;
                                out_mini_offset =
                                    (prev_slab + 1) * prev_slab_size + prev_slab * mini_size;
                                for (unsigned int mini = prev_slab + 1; mini < fanout; mini++) {
                                        memswap(out + out_macro_offset + out_mini_offset,
                                                in + in_mini_offset, mini_size);
                                        in_mini_offset += mini_size;
                                        out_mini_offset += prev_slab_size;
                                }
                                out_macro_offset += SIZE_MACRO;
                        }
                }
                out += slab_size;
        }
}

// This mixing function does not assume access to the entire input to shuffle
// (e.g., because the entire input is produced across a pull of threads). On
// the other hand, this function spreads the output of the encryption produced
// by the single thread across multiple slabs.
//
// This is using a different mixing behavior with respect to the shuffle and
// swap functions above.
void spread_chunks(thread_data *args, int level) {
        if (DEBUG)
                assert(level > args->thread_levels);

        unsigned int fanout = args->mixconfig->diff_factor;
        size_t mini_size    = SIZE_MACRO / fanout;

        unsigned long prev_macros_in_slab = intpow(fanout, level - 1);
        unsigned long macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size             = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size                  = macros_in_slab * SIZE_MACRO;

        unsigned long nof_threads = intpow(fanout, args->total_levels - args->thread_levels);
        unsigned long nof_slabs   = args->seed_size / slab_size;
        unsigned long nof_threads_per_slab      = nof_threads / nof_slabs;
        unsigned long prev_nof_threads_per_slab = nof_threads_per_slab / fanout;

        unsigned long out_slab_offset        = slab_size * (args->thread_id / nof_threads_per_slab);
        unsigned long out_inside_slab_offset = 0;
        if (prev_nof_threads_per_slab > 1) {
                out_inside_slab_offset =
                    args->thread_chunk_size * (args->thread_id % prev_nof_threads_per_slab);
        }
        unsigned long out_mini_offset;
        if (prev_nof_threads_per_slab <= 1) {
                out_mini_offset = mini_size * (args->thread_id % fanout);
        } else {
                out_mini_offset = mini_size * ((args->thread_id % nof_threads_per_slab) /
                                               prev_nof_threads_per_slab);
        }

        byte *in  = args->out;
        byte *out = args->abs_buf + out_slab_offset + out_inside_slab_offset + out_mini_offset;

        unsigned long nof_macros = args->thread_chunk_size / SIZE_MACRO;

        unsigned long in_offset        = 0;
        unsigned long out_macro_offset = 0;

        for (unsigned long macro = 0; macro < nof_macros; macro++) {
                unsigned long out_mini_offset = 0;
                for (unsigned int mini = 0; mini < fanout; mini++) {
                        memcpy(out + out_macro_offset + out_mini_offset, in + in_offset, mini_size);
                        in_offset += mini_size;
                        out_mini_offset += prev_slab_size;
                }
                out_macro_offset += SIZE_MACRO;
        }
}
