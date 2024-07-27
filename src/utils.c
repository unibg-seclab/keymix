#include "utils.h"

#include "config.h"
#include "types.h"
#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

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

inline void reverse_16B(byte *data) {
        size_t size = SIZE_BLOCK;
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

inline void increment_counter(byte *macro, unsigned long step) {
        byte *second_block = macro + SIZE_BLOCK;
        // Note: we reverse because we are on little endian and we want
        // to increment what would be the MSB
        // Maybe there should be a check about this, although it's not that
        // important as of now, or we could just increment the LSB (left side),
        // since the effect is all the same on our schema
        reverse_16B(second_block);
        (*(uint128_t *)second_block) += step;
        reverse_16B(second_block);
}

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline void memxor(void *dst, void *src, size_t size) {
        byte *d = (byte *)dst;
        byte *s = (byte *)src;

        for (; size > 0; size--) {
                *d++ ^= *s++;
        }
}
inline void memxor_ex(void *dst, void *a, void *b, size_t size) {
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
