#include "config.h"
#include "types.h"
#include "utils.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

void print_buffer(byte data[], size_t size, size_t fanout) {
        unsigned int addr = 0;
        printf("%d\t", addr);
        for (int i = 0; i < size; i++) {
                printf("%02x", data[i]);
                if ((i + 1) % (SIZE_MACRO / fanout) == 0) {
                        printf(" | ");
                        addr++;
                }
                if ((i + 1) % SIZE_MACRO == 0) {
                        printf("\n");
                        printf("%d\t", addr);
                }
        }
        printf("\n");
}

int main() {

        size_t diff_factor = 3;
        size_t level       = 3;
        size_t size        = (size_t)pow(diff_factor, level) * SIZE_MACRO;
        byte in[size];
        byte *out_a = malloc(size);
        byte *out_b = malloc(size);
        byte *out_c = malloc(size);

        unsigned int j = 0;
        for (int i = 0; i < size; i++) {
                if (i % 16 == 0)
                        j++;
                in[i]    = j;
                out_a[i] = 0;
                out_b[i] = 0;
                out_c[i] = 0;
        }

        for (unsigned int l = 0; l < level; l++) {
                printf("INPUT\n");
                print_buffer(in, size, diff_factor);

                swap(out_a, in, size, l, diff_factor);
                printf("OUT_A\n");
                print_buffer(out_a, size, diff_factor);

                shuffle(out_b, in, size, l, diff_factor);
                printf("OUT_B\n");
                print_buffer(out_b, size, diff_factor);

                shuffle_opt2(out_c, in, size, l, diff_factor);
                printf("OUT_C\n");
                print_buffer(out_c, size, diff_factor);

                if (memcmp(out_a, out_b, size) != 0) {
                        printf("out_a differs from out_b\n");
                        return 1;
                }
                if (memcmp(out_a, out_c, size) != 0) {
                        printf("out_a differs from out_c\n");
                        return 1;
                }
        }

        free(out_a);
        free(out_b);
        free(out_c);

        return 0;
}
