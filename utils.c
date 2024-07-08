#include <openssl/rand.h>
#include <sys/time.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "types.h"
#include "utils.h"

void memxor(byte *dst, byte *src, size_t n) {
        for (; n > 0; n--) {
                *dst++ ^= *src++;
        }
}

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                printf("(!) Error occured while allocating memory\n");
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

unsigned long get_current_time_millis() {
        struct timeval tp;
        gettimeofday(&tp, NULL);
        unsigned long current_time_millisec = tp.tv_sec * 1000 + tp.tv_usec / 1000;
        return current_time_millisec;
}
