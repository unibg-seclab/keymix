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
        unsigned long dist = SIZE_MACRO;
        for (unsigned int i = 1; i < level; i++) {
                dist *= diff_factor;
        }

        unsigned long bpos;  // block position
        unsigned long nbpos; // new block position
        size_t block_len         = (size_t)(SIZE_MACRO / diff_factor);
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
