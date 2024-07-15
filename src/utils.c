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
void shuffle(byte *restrict out, byte *restrict in, size_t in_size, unsigned int level,
             unsigned int fanout) {
        D assert(level > 0);
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
        D assert(level > 0);

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
