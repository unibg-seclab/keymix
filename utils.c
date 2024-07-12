#include "utils.h"

#include <assert.h>
#include <string.h>

void memxor(byte *dst, byte *src, size_t n) {
        for (; n > 0; n--) {
                *dst++ ^= *src++;
        }
}

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                LOG("(!) Error occured while allocating memory\n");
                // No need to free, as free is a no-op when the ptr is NULL
                exit(1);
        }
        return buf;
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
