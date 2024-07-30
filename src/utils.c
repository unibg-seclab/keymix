#include "utils.h"

#include "types.h"
#include <stdio.h>
#include <string.h>

void safe_explicit_bzero(void *ptr, size_t size) {
        if (ptr) {
                explicit_bzero(ptr, size);
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

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline void memxor(void *dst, void *a, void *b, size_t size) {
        byte *d  = (byte *)dst;
        byte *s1 = (byte *)a;
        byte *s2 = (byte *)b;

        for (; size > 0; size--) {
                *d++ = *s1++ ^ *s2++;
        }
}

inline void memswap(byte *restrict a, byte *restrict b, size_t bytes) {
        byte *a_end = a + bytes;
        while (a < a_end) {
                byte tmp = *a;
                *a++     = *b;
                *b++     = tmp;
        }
}
