#include "utils.h"
#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

void _logf(log_level_t level, const char *fmt, ...) {
        if (level >= LOG_LEVEL) {
                va_list args;
                va_start(args, fmt);
                vfprintf(stderr, fmt, args);
                va_end(args);
        }
}

inline double MiB(size_t size) { return (double)size / 1024 / 1024; }

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline uint64_t total_levels(size_t seed_size, uint32_t diff_factor) {
        uint64_t nof_macros = seed_size / SIZE_MACRO;
        return 1 + LOGBASE(nof_macros, diff_factor);
}

inline void safe_explicit_bzero(void *ptr, size_t size) {
        if (ptr)
                explicit_bzero(ptr, size);
}

inline void memxor(void *dst, void *src, size_t size) {
        byte *d = (byte *)dst;
        byte *s = (byte *)src;

        for (; size > 0; size--) {
                *d++ ^= *s++;
        }
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
void shuffle(byte *restrict out, byte *restrict in, size_t in_size, uint32_t level,
             uint32_t fanout) {
        if (DEBUG)
                assert(level > 0);
        size_t mini_size        = SIZE_MACRO / fanout;
        byte *last              = out + in_size;
        uint64_t macros_in_slab = intpow(fanout, level);
        size_t slab_size        = macros_in_slab * SIZE_MACRO;

        _log(LOG_DEBUG, "Moving pieces of %zu B\n", mini_size);
        _log(LOG_DEBUG, "Over a total of %zu slabs\n", in_size / slab_size);

        for (; out < last; out += slab_size, in += slab_size) {
                _log(LOG_DEBUG, "New slab\n");

                for (uint64_t j = 0; j < (slab_size / mini_size); j++) {
                        uint64_t i = macros_in_slab * (j % fanout) + j / fanout;
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
void shuffle_opt(byte *restrict out, byte *restrict in, size_t in_size, uint32_t level,
                 uint32_t fanout) {
        if (DEBUG)
                assert(level > 0);

        size_t mini_size        = SIZE_MACRO / fanout;
        byte *last              = out + in_size;
        uint64_t macros_in_slab = intpow(fanout, level);
        size_t slab_size        = macros_in_slab * SIZE_MACRO;

        uint64_t i           = 0;
        uint64_t i_increment = mini_size * macros_in_slab;

        while (out < last) {
                for (uint64_t k = 0; k < macros_in_slab; k++) {
                        // This is split around, but essentialy
                        // calculates
                        //        i = macros_in_slab * mod + k;
                        // for mod and k starting both from 0
                        // We reset i to mini_size * k every time k changes,
                        // and increment it by mini_size * macros_in_slab
                        // for every mod. In this way, we use less multiplications.
                        i = mini_size * k;
                        for (uint64_t mod = 0; mod < fanout; mod++) {
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
void shuffle_chunks(thread_data *args, uint32_t level) {
        uint32_t fanout = args->mixconfig->diff_factor;

        size_t mini_size    = SIZE_MACRO / fanout;
        uint64_t nof_macros = args->thread_chunk_size / SIZE_MACRO;

        uint32_t macros_in_slab = intpow(fanout, level);
        size_t slab_size        = macros_in_slab * SIZE_MACRO;

        byte *in  = args->out;
        byte *out = args->abs_buf;

        byte *in_abs = args->abs_out;

        uint64_t in_offset = 0;
        uint64_t src_abs, src_rel, dst_abs, dst_rel;

        for (uint64_t macro = 0; macro < nof_macros; macro++) {
                for (uint32_t mini = 0; mini < fanout; mini++) {
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
void shuffle_chunks_opt(thread_data *args, uint32_t level) {
        uint32_t fanout = args->mixconfig->diff_factor;

        size_t mini_size        = SIZE_MACRO / fanout;
        uint64_t macros_in_slab = intpow(fanout, level);
        uint64_t minis_in_slab  = fanout * macros_in_slab;

        byte *in      = args->out;
        byte *in_abs  = args->abs_out;
        byte *last    = in + args->thread_chunk_size;
        byte *out_abs = args->abs_buf;

        uint64_t minis_from_origin = (in - in_abs) / mini_size;
        uint64_t src               = minis_from_origin % minis_in_slab;

        while (in < last) {
                uint64_t dst = fanout * (src % macros_in_slab) + src / macros_in_slab;
                memcpy(out_abs + dst * mini_size, in, mini_size);

                in += mini_size;
                src++;
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
void spread(byte *restrict out, byte *restrict in, size_t in_size, uint32_t level,
            uint32_t fanout) {
        if (DEBUG)
                assert(level > 0);

        size_t mini_size = SIZE_MACRO / fanout;

        uint64_t prev_macros_in_slab = intpow(fanout, level - 1);
        uint64_t macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

        byte *last         = out + in_size;
        uint64_t in_offset = 0;
        uint64_t out_macro_offset, out_mini_offset;

        while (out < last) {
                for (uint32_t prev_slab = 0; prev_slab < fanout; prev_slab++) {
                        out_macro_offset = 0;
                        for (uint64_t macro = 0; macro < prev_macros_in_slab; macro++) {
                                out_mini_offset = prev_slab * mini_size;
                                for (uint32_t mini = 0; mini < fanout; mini++) {
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

void memswap(byte *restrict a, byte *restrict b, size_t bytes) {
        byte *a_end = a + bytes;
        while (a < a_end) {
                byte tmp = *a;
                *a++     = *b;
                *b++     = tmp;
        }
}

// This function spreads the output of the encryption produced by
// the single thread across multiple slabs inplace.
void spread_inplace(byte *restrict buffer, size_t in_size, uint32_t level, uint32_t fanout) {
        if (DEBUG) {
                assert(level > 0);
        }

        byte *in  = buffer;
        byte *out = buffer;

        size_t mini_size = SIZE_MACRO / fanout;

        uint64_t prev_macros_in_slab = intpow(fanout, level - 1);
        uint64_t macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

        byte *last = out + in_size;
        uint64_t in_mini_offset, out_macro_offset, out_mini_offset;

        while (out < last) {
                // With inplace swap we never have to look back on the previous
                // slab parts. Moreover, when we get to the last slab part we
                // have nothing to do, previous swap operations have already
                // managed to set this last slab part right.
                in_mini_offset = 0;
                for (uint32_t prev_slab = 0; prev_slab < fanout - 1; prev_slab++) {
                        out_macro_offset = 0;
                        for (uint64_t macro = 0; macro < prev_macros_in_slab; macro++) {
                                in_mini_offset += (prev_slab + 1) * mini_size;
                                out_mini_offset =
                                    (prev_slab + 1) * prev_slab_size + prev_slab * mini_size;
                                for (uint32_t mini = prev_slab + 1; mini < fanout; mini++) {
                                        memswap(out + out_macro_offset + out_mini_offset,
                                                in + in_mini_offset, mini_size);
                                        in_mini_offset += mini_size;
                                        out_mini_offset += prev_slab_size;
                                }
                                out_macro_offset += SIZE_MACRO;
                        }
                }
                in += slab_size;
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
void spread_chunks(thread_data *args, uint32_t level) {
        if (DEBUG)
                assert(level >= args->thread_levels);

        uint32_t fanout  = args->mixconfig->diff_factor;
        size_t mini_size = SIZE_MACRO / fanout;

        uint64_t prev_macros_in_slab = intpow(fanout, level - 1);
        uint64_t macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

        uint64_t nof_threads          = intpow(fanout, args->total_levels - args->thread_levels);
        uint64_t nof_slabs            = args->seed_size / slab_size;
        uint64_t nof_threads_per_slab = nof_threads / nof_slabs;
        uint64_t prev_nof_threads_per_slab = nof_threads_per_slab / fanout;

        uint64_t prev_slab;
        if (prev_nof_threads_per_slab <= 1) {
                prev_slab = args->thread_id % fanout;
        } else {
                prev_slab = (args->thread_id % nof_threads_per_slab) / prev_nof_threads_per_slab;
        }

        uint64_t out_slab_offset        = slab_size * (args->thread_id / nof_threads_per_slab);
        uint64_t out_inside_slab_offset = 0;
        if (prev_nof_threads_per_slab > 1) {
                out_inside_slab_offset =
                    args->thread_chunk_size * (args->thread_id % prev_nof_threads_per_slab);
        }
        uint64_t out_mini_offset = prev_slab * mini_size;

        byte *in  = args->out;
        byte *out = args->abs_buf + out_slab_offset + out_inside_slab_offset + out_mini_offset;

        uint64_t nof_macros = args->thread_chunk_size / SIZE_MACRO;

        uint64_t in_offset        = 0;
        uint64_t out_macro_offset = 0;

        for (uint64_t macro = 0; macro < nof_macros; macro++) {
                uint64_t out_mini_offset = 0;
                for (uint32_t mini = 0; mini < fanout; mini++) {
                        memcpy(out + out_macro_offset + out_mini_offset, in + in_offset, mini_size);
                        in_offset += mini_size;
                        out_mini_offset += prev_slab_size;
                }
                out_macro_offset += SIZE_MACRO;
        }
}

// Spread the output of the encryption owned by the current thread to the
// following threads belonging to the same slab. The operation despite being
// done inplace is thread-safe since there is no overlap between the read and
// write operations of the threads.
//
// Note, this is using a different mixing behavior with respect to the shuffle
// functions above.
void spread_chunks_inplace(thread_data *args, uint32_t level) {
        if (DEBUG)
                assert(level >= args->thread_levels);

        uint32_t fanout  = args->mixconfig->diff_factor;
        size_t mini_size = SIZE_MACRO / fanout;

        uint64_t prev_macros_in_slab = intpow(fanout, level - 1);
        uint64_t macros_in_slab      = fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

        uint64_t nof_threads          = intpow(fanout, args->total_levels - args->thread_levels);
        uint64_t nof_slabs            = args->seed_size / slab_size;
        uint64_t nof_threads_per_slab = nof_threads / nof_slabs;
        uint64_t prev_nof_threads_per_slab = nof_threads_per_slab / fanout;

        uint64_t prev_slab;
        if (prev_nof_threads_per_slab <= 1) {
                prev_slab = args->thread_id % fanout;
        } else {
                prev_slab = (args->thread_id % nof_threads_per_slab) / prev_nof_threads_per_slab;
        }

        // Don't do anything if the current thread belongs to the last
        // prev_slab.
        // Note, this inevitably reduces the amount of parallelism we can
        // accomplish.
        if (prev_slab == fanout - 1) {
                return;
        }

        uint64_t out_slab_offset        = slab_size * (args->thread_id / nof_threads_per_slab);
        uint64_t out_inside_slab_offset = 0;
        if (prev_nof_threads_per_slab > 1) {
                out_inside_slab_offset =
                    args->thread_chunk_size * (args->thread_id % prev_nof_threads_per_slab);
        }
        uint64_t out_mini_offset = prev_slab * mini_size;

        byte *in  = args->out;
        byte *out = args->abs_out + out_slab_offset + out_inside_slab_offset + out_mini_offset;

        uint64_t nof_macros = args->thread_chunk_size / SIZE_MACRO;

        uint64_t in_mini_offset   = 0;
        uint64_t out_macro_offset = 0;

        for (uint64_t macro = 0; macro < nof_macros; macro++) {
                // Note, differently from the 'normal' implementation of the
                // spread_chunks, here we do not look back on previous parts of
                // the slab. Indeed, previous threads take care of them.
                in_mini_offset += (prev_slab + 1) * mini_size;
                out_mini_offset = (prev_slab + 1) * prev_slab_size; // + prev_slab * mini_size;
                for (uint32_t mini = prev_slab + 1; mini < fanout; mini++) {
                        memswap(out + out_macro_offset + out_mini_offset, in + in_mini_offset,
                                mini_size);
                        in_mini_offset += mini_size;
                        out_mini_offset += prev_slab_size;
                }
                out_macro_offset += SIZE_MACRO;
        }
}