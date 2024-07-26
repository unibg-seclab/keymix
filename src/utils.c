#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

#include "config.h"
#include "types.h"

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                printf("(!) Error occured while allocating memory\n");
                // No need to free, as free is a no-op when the ptr is NULL
                exit(1);
        }
        return buf;
}

// max 2^64 times
void increment_counter(byte *macro, unsigned long step) {
        counter ctr;
        for (unsigned short p = 0; p < 8; p++)
                ctr.array[8 - 1 - p] = (macro + 24)[p];
        ctr.value += step;
        for (unsigned short p = 0; p < 8; p++)
                (macro + 24)[p] = ctr.array[8 - 1 - p];
}

size_t get_file_size(FILE *fstr) {
        if (fstr == NULL) {
                return 0;
        }
        // move the cursor to the end of the file
        if (fseek(fstr, 0, SEEK_END) < 0) {
                return 0;
        }
        // get the current offset
        long size = ftell(fstr);
        // move the cursor back to the beginning of the file
        if (fseek(fstr, 0, SEEK_SET) < 0) {
                // undefined behavior if code enters this branch
                printf("(!) fseek cannot set the cursor to the beginning of the buffer\n");
                exit(errno);
        }
        return size;
}

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline uint8_t total_levels(size_t seed_size, uint8_t diff_factor) {
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
inline void memxor_ex(void *dst, void *a, void *b, size_t size) {
        byte *d  = (byte *)dst;
        byte *s1 = (byte *)a;
        byte *s2 = (byte *)b;

        for (; size > 0; size--) {
                *d++ = *s1++ ^ *s2++;
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
void spread_inplace(byte *buffer, size_t size, uint8_t level, uint8_t fanout) {
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
                                out_macro_offset += SIZE_MACRO;
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
void spread_chunks_inplace(spread_inplace_chunks_t *args, uint8_t level) {
        if (DEBUG)
                assert(level >= args->thread_levels);

        size_t mini_size = SIZE_MACRO / args->fanout;

        uint64_t prev_macros_in_slab = intpow(args->fanout, level - 1);
        uint64_t macros_in_slab      = args->fanout * prev_macros_in_slab;
        size_t prev_slab_size        = prev_macros_in_slab * SIZE_MACRO;
        size_t slab_size             = macros_in_slab * SIZE_MACRO;

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

        uint64_t nof_macros = args->buffer_size / SIZE_MACRO;

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
                out_macro_offset += SIZE_MACRO;
        }
}
