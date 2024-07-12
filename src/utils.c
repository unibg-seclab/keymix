#include "utils.h"

#include <assert.h>
#include <math.h>
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

void shuffle(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout) {
        // If we interpret in and out a series of mini_blocks, each single one
        // of size SIZE_MACRO / fanout, then the formula to shuffle them is actually quite simple
        //
        // Consider the first (fanout ^ level) macro-blocks
        //    for each j in the indexes of the out part in this frist macro-blocks
        //        i = (fanout ^ level) * (j % fanout) + floor(j / fanout)
        //        out[j] = in[j]
        // And then repeat for the remaining, with the approriate offset

        size_t mini_size = SIZE_MACRO / fanout;

        byte *last              = out + in_size;
        size_t fanout_exp_level = pow(fanout, level);

        size_t slab_size = fanout_exp_level * SIZE_MACRO;

        D printf("Moving pieces of %zu B\n", mini_size);
        D printf("Over a total of %zu slabs\n", in_size / slab_size);

        for (; out < last; out += slab_size, in += slab_size) {
                D printf("New slab\n");

                for (size_t j = 0; j < (slab_size / mini_size); j++) {
                        size_t i = fanout_exp_level * (j % fanout) + j / fanout;
                        D printf("%zu -> %zu\n", i, j);
                        memcpy(out + j * mini_size, in + i * mini_size, mini_size);
                }
        }
}

// This is the same as the previous one, but trying to optimize the stuff
void shuffle_opt(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int fanout) {
        size_t mini_size = SIZE_MACRO / fanout;
        byte *last       = out + in_size;
        // size
}

void swap(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int diff_factor) {
        if (level == 0) {
                return;
        }

        // divide the input into slabs based on the diff_factor
        unsigned long prev_slab_blocks = diff_factor;
        for (unsigned int i = 1; i < level; i++) {
                prev_slab_blocks *= diff_factor;
        }
        unsigned long slab_blocks = prev_slab_blocks * diff_factor;
        size_t size_slab          = slab_blocks * SIZE_BLOCK;
        unsigned long nof_slabs   = in_size / size_slab;
        size_t prev_slab_size     = SIZE_BLOCK * prev_slab_blocks;

        D printf("swap, level %d, diff_factor %d, prev_slab_blocks %ld, slab_blocks %ld, slab_size "
                 "%ld, in_size %ld\n",
                 level, diff_factor, prev_slab_blocks, slab_blocks, size_slab, in_size);

        unsigned long block = 0;
        size_t OFFSET_SLAB  = 0;
        for (; nof_slabs > 0; nof_slabs--) {
                for (unsigned long psb = 0; psb < prev_slab_blocks; psb++) {
                        for (unsigned int u = 0; u < diff_factor; u++) {
                                memcpy(out + block * SIZE_BLOCK,
                                       in + OFFSET_SLAB + psb * SIZE_BLOCK + prev_slab_size * u,
                                       SIZE_BLOCK);
                                block++;
                        }
                }
                OFFSET_SLAB += size_slab;
        }
}

void swap_chunks(thread_data *args, int level) {

        unsigned long prev_slab_blocks = args->diff_factor;
        for (unsigned int i = 1; i < level; i++) {
                prev_slab_blocks *= args->diff_factor;
        }
        size_t prev_slab_size         = SIZE_BLOCK * prev_slab_blocks;
        size_t size_slab              = prev_slab_blocks * args->diff_factor * SIZE_BLOCK;
        unsigned long chunk_blocks    = args->thread_chunk_size / SIZE_BLOCK;
        unsigned long chunk_start_pos = args->thread_id * args->thread_chunk_size;
        unsigned long slab_start_pos  = 0;
        while (slab_start_pos + size_slab <= chunk_start_pos) {
                slab_start_pos += size_slab;
        }
        unsigned int psrid = (chunk_start_pos - slab_start_pos) / prev_slab_size;
        unsigned long UPFRONT_BLOCKS_OFFSET =
            (chunk_start_pos - slab_start_pos - psrid * prev_slab_size) * args->diff_factor;

        size_t OFFSET = slab_start_pos + UPFRONT_BLOCKS_OFFSET;

        D printf("swap, level %d, thread_id %d, diff_factor %d, thread_id %d, PREV_SLAB_SIZE %ld, "
                 "SIZE_SLAB %ld, "
                 "chunk_size %ld, OFFSET %ld\n",
                 level, args->thread_id, args->diff_factor, args->thread_id, prev_slab_size,
                 size_slab, args->thread_chunk_size, OFFSET);

        for (unsigned long block; block < chunk_blocks; block++) {
                memcpy(args->abs_swp + OFFSET, args->out + block * SIZE_BLOCK, SIZE_BLOCK);
                OFFSET += SIZE_MACRO;
        }
}
