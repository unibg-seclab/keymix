#include "utils.h"

#include "config.h"
#include <openssl/rand.h>

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

void set_zero(byte *buf, size_t size) {
        for (unsigned int i = 0; i < size; i++) {
                buf[i] = 0;
        }
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
