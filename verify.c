#include "config.h"
#include "types.h"
#include "utils.h"
#include <math.h>
#include <stdio.h>

void print_buffer(byte data[], size_t size, size_t fanout) {
        for (int i = 0; i < size; i++) {
                printf("%02x", data[i]);
                if ((i + 1) % (SIZE_MACRO / fanout) == 0)
                        printf(" | ");
                if ((i + 1) % SIZE_MACRO == 0)
                        printf("\n");
        }
}
inline size_t intpow(size_t base, size_t exp) {
        size_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

int main() {
        size_t fanout = 3;
        size_t level  = 2;
        size_t size   = 9 * SIZE_MACRO;
        byte in[size];
        byte out_a[size];
        byte out_b[size];

        for (int i = 0; i < size; i++) {
                in[i]    = i;
                out_a[i] = out_b[i] = 0;
        }

        print_buffer(in, size, fanout);

        shuffle(out_a, in, size, level, fanout);
        printf("---\n");
        print_buffer(out_a, size, fanout);
        shuffle_opt(out_b, in, size, level, fanout);
        printf("---\n");
        print_buffer(out_b, size, fanout);

        // Remember, for Mix&Slice
        // Macro = our entire key
        // Block = our macro
        // Mini  = our fractino of the macro
        // size_t mini_size      = size / fanout;
        // size_t mini_per_block = fanout;
        // size_t mini_per_macro = mini_per_block * 3;
        // size_t dof            = log2(mini_per_block);
        // size_t digits         = log2(mini_per_macro);
        // SHUFFLE(1, off, bp, in, out_bacis, bp, in + off);

        // printf("%d\n", memcmp(out_swap, out_bacis, size));
        return 0;
}
