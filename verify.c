#include "config.h"
#include "types.h"
#include "utils.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

#define MIN_LEVEL 1
#define MAX_LEVEL 13

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
        srand(time(NULL));

        byte *in              = NULL;
        byte *out_swap        = NULL;
        byte *out_shuffle     = NULL;
        byte *out_shuffle_opt = NULL;
        int err               = 0;

        for (size_t fanout = 2; fanout <= 4; fanout++)
                for (size_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        size_t size     = (size_t)pow(fanout, l) * SIZE_MACRO;
                        in              = realloc(in, size);
                        out_swap        = realloc(out_swap, size);
                        out_shuffle     = realloc(out_shuffle, size);
                        out_shuffle_opt = realloc(out_shuffle_opt, size);

                        // Setup random data, reset out

                        for (int i = 0; i < size; i++) {
                                in[i]              = rand() % 256;
                                out_swap[i]        = 0;
                                out_shuffle[i]     = 0;
                                out_shuffle_opt[i] = 0;
                        }

                        // Do all the versions

                        err = 0;

                        swap(out_swap, in, size, l, fanout);
                        shuffle(out_shuffle, in, size, l, fanout);
                        shuffle_opt(out_shuffle_opt, in, size, l, fanout);

                        if (memcmp(out_swap, out_shuffle, size)) {
                                printf("Swap and shuffle are different!\n");
                                err += 1;
                        }
                        if (memcmp(out_shuffle, out_shuffle_opt, size)) {
                                printf("Shuffle and shuffle_opt are different!\n");
                                err += 2;
                        }

                        if (err)
                                goto cleanup;
                }

cleanup:
        free(out_swap);
        free(out_shuffle);
        free(out_shuffle_opt);

        if (!err)
                printf("All ok\n");

        return err;
}

// Use this to measure stuff, but try and leave verify.c to do only the
// verification

// double t;
// double size_mib = (double)size / 1024 / 1024;

// printf("-------- fanout %zu, size %.2f MiB (13th level)\n", fanout,
//        size_mib);
// t = MEASURE(swap(out_swap, in, size, l, fanout));
// printf("Swap             %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
// t = MEASURE(shuffle(out_shuffle, in, size, l, fanout));
// printf("Shuffle          %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
// t = MEASURE(shuffle_opt(out_shuffle_opt, in, size, l, fanout));
// printf("Shuffle (opt)    %-5.2f (%5.2f MiB/s)\n", t, size_mib / (t / 1000));
