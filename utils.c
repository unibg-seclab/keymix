#include "utils.h"

#include <openssl/rand.h>
#include <wolfssl/wolfcrypt/aes.h>

void memxor(byte *dst, byte *src, size_t n) {
        for (; n > 0; n--) {
                *dst++ ^= *src++;
        }
}

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                printf("(!) Error occured while allocating memory\n");
                free(buf);
                exit(1);
        }
        return buf;
}

byte *generate_random_bytestream(int num_bytes) {
        byte *buf   = (byte *)malloc(num_bytes);
        int success = RAND_bytes(buf, num_bytes);
        if (!success) {
                free(buf);
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

        unsigned long dist = 1;
        for (unsigned int i = 0; i <= level; i++) {
                dist *= diff_factor;
        }

        unsigned int spos;  // slab position
        unsigned int bpos;  // block position
        unsigned int nbpos; // new block position

        for (unsigned int slab = 0; slab < in_size / (AES_BLOCK_SIZE * diff_factor); slab++) {
                spos = slab * AES_BLOCK_SIZE * diff_factor;
                // 1st block never moves
                for (unsigned int block = 1; block < diff_factor; block++) {
                        bpos = (unsigned int)slab + block * AES_BLOCK_SIZE;
                        nbpos =
                            (unsigned int)(((unsigned long)bpos + AES_BLOCK_SIZE * block * dist) &
                                           in_size);
                        // copy the block to the new position
                        memcpy(out + nbpos, in + bpos, (size_t)(SIZE_MACRO / diff_factor));
                }
        }
}
