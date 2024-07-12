#include "config.h"
#include "types.h"
#include "utils.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

void print_buffer(byte data[], size_t size, size_t fanout) {
        for (int i = 0; i < size; i++) {
                printf("%02x", data[i]);
                if ((i + 1) % (SIZE_MACRO / fanout) == 0)
                        printf(" | ");
                if ((i + 1) % SIZE_MACRO == 0)
                        printf("\n");
        }
}

int main() {
        srand(time(NULL));

        size_t fanout = 3;
        size_t level  = 2;
        size_t size   = (size_t)pow(fanout, level) * SIZE_MACRO;
        byte in[size];
        byte *out_a = malloc(size);
        byte *out_b = malloc(size);

        for (int i = 0; i < size; i++) {
                in[i]    = rand() % 256;
                out_a[i] = 0;
                out_b[i] = 0;
        }

        shuffle(out_a, in, size, level, fanout);
        // shuffle_opt(out_b, in, size, level, fanout);
        shuffle_opt2(out_b, in, size, level, fanout);

        if (memcmp(out_a, out_b, size) != 0)
                return 1;

        free(out_a);
        free(out_b);
        return 0;
}
