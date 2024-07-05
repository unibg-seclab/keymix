#include "utils.h"

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
        // dist = diff_factor ^ (level + 1)
        size_t dist = 1;
        for (int i = 0; i <= level; i++) {
                dist *= diff_factor;
        }

        size_t spos;  // slab position
        size_t bpos;  // block position
        size_t nbpos; // new block position

        for (unsigned int slab = 0; slab < in_size / (SIZE_BLOCK * diff_factor); slab++) {
                spos = slab * SIZE_BLOCK * diff_factor;
                // 1st block, copy without move
                memcpy(out + slab, in + slab, (size_t)(SIZE_MACRO / diff_factor));
                // 2nd to last blocks, move
                for (unsigned int block = 1; block < diff_factor; block++) {
                        bpos  = slab + block * SIZE_BLOCK;
                        nbpos = bpos + SIZE_BLOCK * block * dist;
                        while (nbpos >= in_size)
                                nbpos -= in_size;
                        // copy the block to the new position
                        memcpy(out + nbpos, in + bpos, SIZE_MACRO / diff_factor);
                }
        }
}
