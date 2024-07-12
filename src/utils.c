#include "utils.h"

#include <assert.h>
#include <string.h>

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

void swap_seed(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int diff_factor) {
        D assert(level > 0);

        size_t size_to_move = SIZE_MACRO / diff_factor;

        // divide the input into slabs based on the diff_factor
        unsigned long prev_slab_blocks = diff_factor;
        for (unsigned int i = 1; i < level; i++) {
                prev_slab_blocks *= diff_factor;
        }
        unsigned long slab_blocks = prev_slab_blocks * diff_factor;
        size_t SIZE_SLAB          = slab_blocks * size_to_move;
        unsigned long nof_slabs   = in_size / SIZE_SLAB;
        size_t PREV_SLAB_SIZE     = size_to_move * prev_slab_blocks;

        unsigned long block = 0;
        size_t OFFSET_SLAB  = 0;
        for (; nof_slabs > 0; nof_slabs--) {
                for (unsigned long psb = 0; psb < prev_slab_blocks; psb++) {
                        for (unsigned int u = 0; u < diff_factor; u++) {
                                memcpy(out + block * size_to_move,
                                       in + OFFSET_SLAB + psb * size_to_move + PREV_SLAB_SIZE * u,
                                       size_to_move);
                                block++;
                        }
                }
                OFFSET_SLAB += SIZE_SLAB;
        }
}

void swap_cyclic(byte *out, byte *in, size_t in_size, unsigned int level,
                 unsigned int diff_factor) {
        D assert(level > 0);

        unsigned long dist = SIZE_MACRO;
        for (unsigned int i = 1; i < level; i++) {
                dist *= diff_factor;
        }

        unsigned long bpos;  // block position
        unsigned long nbpos; // new block position
        size_t block_len         = SIZE_MACRO / diff_factor;
        unsigned long nof_macros = in_size / SIZE_MACRO;

        unsigned long mpos = 0;
        for (unsigned int m = 0; m < nof_macros; m++) {
                // 1st block in macro
                memcpy(out + mpos, in + mpos, block_len);
                // 2nd to last blocks in macro
                for (unsigned int b = 1; b < diff_factor; b++) {
                        bpos  = mpos + b * block_len;
                        nbpos = bpos + b * dist;
                        if (nbpos > in_size - 1) {
                                nbpos -= in_size;
                        }
                        memcpy(out + nbpos, in + bpos, block_len);
                }
                mpos += SIZE_MACRO;
        }
}
