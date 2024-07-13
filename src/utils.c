#include "utils.h"
#include "config.h"

#include <assert.h>
#include <string.h>
#include <sys/time.h>

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                LOG("(!) Error occured while allocating memory\n");
                // No need to free, as free is a no-op when the ptr is NULL
                exit(1);
        }
        return buf;
}

void print_buffer_hex(byte *buf, size_t size, char *descr) {
        printf("%s\n", descr);
        for (size_t i = 0; i < size; i++) {
                if (i % 16 == 0) {
                        printf("|");
                }
                printf("%02x", buf[i]);
        }
        printf("|\n");
}

inline size_t intpow(size_t base, size_t exp) {
        size_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

void shuffle(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
             unsigned int fanout) {
        // If we interpret in and out a series of mini_blocks, each single one
        // of size SIZE_MACRO / fanout, then the formula to shuffle them is actually quite simple
        //
        // Consider the first (fanout ^ level) macro-blocks
        //    for each j in the indexes of the out part in this frist macro-blocks
        //        i = (fanout ^ level) * (j % fanout) + floor(j / fanout)
        //        out[j] = in[j]
        // And then repeat for the remaining, with the approriate offset
        size_t mini_size      = SIZE_MACRO / fanout;
        byte *last            = out + in_size;
        size_t macros_in_slab = intpow(fanout, level);
        size_t slab_size      = macros_in_slab * SIZE_MACRO;

        D printf("Moving pieces of %zu B\n", mini_size);
        D printf("Over a total of %zu slabs\n", in_size / slab_size);

        for (; out < last; out += slab_size, in += slab_size) {
                D printf("New slab\n");

                for (size_t j = 0; j < (slab_size / mini_size); j++) {
                        size_t i = macros_in_slab * (j % fanout) + j / fanout;
                        D printf("%zu -> %zu\n", i, j);
                        memcpy(out + j * mini_size, in + i * mini_size, mini_size);
                }
        }
}

// This is the same as the previous one, but trying to optimize the stuff
void shuffle_opt(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
                 unsigned int fanout) {
        size_t mini_size      = SIZE_MACRO / fanout;
        byte *last            = out + in_size;
        size_t macros_in_slab = intpow(fanout, level);
        size_t slab_size      = macros_in_slab * SIZE_MACRO;

        for (; out < last; out += slab_size, in += slab_size) {
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

                // In this way, there are no fractions and no modules computed
                // every time

                for (size_t k = 0; k < macros_in_slab; k++) {
                        for (size_t mod = 0; mod < fanout; mod++) {
                                size_t i = macros_in_slab * mod + k;
                                size_t j = fanout * k + mod;
                                memcpy(out + j * mini_size, in + i * mini_size, mini_size);
                        }
                }
        }
}

// Let's start cheating
// 1. We can user `restrict` for the input pointer to tell the compiler
//    that `out` and `in` will always and surely point to different areas
//    in memory. This is ok for us, we don't want any overlapping on those two.
// 2. The formula from shuffle can be transformed to (knowing that a % b = a - b * (a / b) if a,b
//    are integers)
//        i = d^l * j + (1 - d^(l+1)) * (j/d)
//                      ^^^^^^^^^^^^^ This is surely negative, let's make it positive
//          = d^l * j - (d^(l+1) - 1) * (j/d) = aj - b(j/d)
//    so we can precompute the necessary multipliers.
//    Note that in the code d^l = macros_in_slab, while d^(l+1) = macros_in_slab * fanout =
// 3. It's true that j = fanout * k + mod, but we can just make j start from 0
//    at each new slab and increment it
// 4. Since we go over `out` linearly, in order, we can just increment `out`
//    by mini_size every time, instead of jumping a slab_size and then updating
//    the individual elements one by one. This does not hold for `in`.
// 5. As said in the previous shuffle_opt,
//        tot_js = slab_size / mini_size = fanout^(level+1) = b + 1
// 6. We can multiply a and b directly by mini_size, so that we don't do
//    a lot of multiplications internally. j must always remain a "simple" integer.
// 7. We don't have to calculate j/fanout every single time, since the fanout
//    is known and j always has the same values. If we take this idea into
//    account, we can setup already all the possible values that aj - b(j/fanout)
//    takes once, before doing the for again and again.
//    I am not 100% sure this is faster than just recomputing (since we need to malloc)
//    but I'll try it and leave the old code commented. We could try an array,
//    but if it's too big it will error out.
void shuffle_opt2(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
                  unsigned int fanout) {
        size_t mini_size      = SIZE_MACRO / fanout;
        byte *last            = out + in_size;
        size_t macros_in_slab = intpow(fanout, level);
        size_t slab_size      = macros_in_slab * SIZE_MACRO;

        size_t a      = mini_size * macros_in_slab;
        size_t tot_js = macros_in_slab * fanout;
        size_t b      = mini_size * (tot_js - 1);

        size_t *is = malloc(tot_js * sizeof(size_t));
        for (size_t j = 0; j < tot_js; j++) {
                is[j] = a * j - b * (j / fanout);
        }

        while (out < last) {
                for (size_t j = 0; j < tot_js; j++) {
                        // size_t i = a * j - b * (j / fanout);
                        // memcpy(out, in + i, mini_size);
                        memcpy(out, in + is[j], mini_size);
                        out += mini_size;
                }
                in += slab_size;
        }

        free(is);
}
/* void shuffle_opt2(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level, */
/*                   unsigned int fanout) { */
/*         size_t mini_size      = SIZE_MACRO / fanout; */
/*         byte *last            = out + in_size; */
/*         size_t macros_in_slab = intpow(fanout, level); */
/*         size_t slab_size      = macros_in_slab * SIZE_MACRO; */

/*         size_t j; */
/*         size_t a = macros_in_slab; */
/*         size_t b = slab_size - 1; */

/*         while (out < last) { */
/*                 j = 0; */

/*                 for (size_t k = 0; k < macros_in_slab; k++) { */
/*                         for (size_t mod = 0; mod < fanout; mod++) { */
/*                                 // size_t i = macros_in_slab * mod + k; */
/*                                 size_t i = a * j + b * (j / fanout); */
/*                                 memcpy(out, in + i * mini_size, mini_size); */
/*                                 j++; // We must increment by 1, otherwise the formula for i does
 * not */
/*                                      // work */
/*                                 out += mini_size; */
/*                         } */
/*                 } */

/*                 in += slab_size; */
/*         } */
/* } */

void swap(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
          unsigned int diff_factor) {
        if (level == 0) {
                return;
        }

        int size_block = SIZE_MACRO / diff_factor;

        // divide the input into slabs based on the diff_factor
        unsigned long prev_slab_blocks = intpow(diff_factor, level);
        size_t slab_size               = prev_slab_blocks * diff_factor * size_block;
        unsigned long nof_slabs        = in_size / slab_size;
        size_t prev_slab_size          = size_block * prev_slab_blocks;

        D printf("swap, level %d, diff_factor %d, prev_slab_blocks %ld, slab_size "
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

void swap_chunks(thread_data *args, int level) {
        int size_block = SIZE_MACRO / args->diff_factor;

        size_t prev_slab_size = size_block;
        for (unsigned int i = 0; i < level; i++) {
                prev_slab_size *= args->diff_factor;
        }
        size_t slab_size              = args->diff_factor * prev_slab_size;
        unsigned long chunk_blocks    = args->thread_chunk_size / size_block;
        unsigned long chunk_start_pos = args->thread_id * args->thread_chunk_size;
        unsigned long slab_start_pos  = chunk_start_pos - chunk_start_pos % slab_size;
        unsigned long UPFRONT_BLOCKS_OFFSET =
            args->diff_factor * (chunk_start_pos % prev_slab_size);

        size_t OFFSET = slab_start_pos + UPFRONT_BLOCKS_OFFSET;

        D printf("swap, level %d, thread_id %d, diff_factor %d, thread_id %d, PREV_SLAB_SIZE %ld, "
                 "SIZE_SLAB %ld, "
                 "chunk_size %ld, OFFSET %ld\n",
                 level, args->thread_id, args->diff_factor, args->thread_id, prev_slab_size,
                 slab_size, args->thread_chunk_size, OFFSET);

        for (unsigned long block = 0; block < chunk_blocks; block++) {
                memcpy(args->abs_swp + OFFSET, args->out + block * size_block, size_block);
                OFFSET += SIZE_MACRO;
        }
}
