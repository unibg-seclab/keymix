#include "aesni.h"
#include "config.h"
#include "keymix.h"
#include "openssl.h"
#include "types.h"
#include "utils.h"
#include "wolfssl.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

#define MIN_LEVEL 1
#define MAX_LEVEL 10

#define COMPARE(a, b, size, msg)                                                                   \
        if (memcmp(a, b, size)) {                                                                  \
                printf(msg);                                                                       \
                err++;                                                                             \
        }

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

        byte *in    = NULL;
        byte *out_a = NULL;
        byte *out_b = NULL;
        byte *out_c = NULL;

        int err = 0;

        for (size_t fanout = 2; fanout <= 4; fanout++) {
                for (size_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                        printf("  Fanout %zu, level %zu...\n", fanout, l);
                        size_t size = (size_t)pow(fanout, l) * SIZE_MACRO;
                        in          = realloc(in, size);
                        out_a       = realloc(out_a, size);
                        out_b       = realloc(out_b, size);
                        out_c       = realloc(out_c, size);

                        // Setup random data, reset out

                        for (int i = 0; i < size; i++) {
                                in[i]    = rand() % 256;
                                out_a[i] = 0;
                                out_b[i] = 0;
                                out_c[i] = 0;
                        }

                        // Validate swap/shuffle equivalence *at the specific level*

                        err = 0;

                        swap(out_a, in, size, l, fanout);
                        shuffle(out_b, in, size, l, fanout);
                        shuffle_opt(out_c, in, size, l, fanout);

                        COMPARE(out_a, out_b, size, "Swap    != shuffle\n");
                        COMPARE(out_b, out_c, size, "Shuffle != shuffle (opt)\n");
                        COMPARE(out_a, out_c, size, "Swap    != shuffle (opt)\n")

                        if (err)
                                goto cleanup;
                        printf("  > [SWAPS OK]\n");

                        // Validate keymix/keymix2 equivalence with various
                        // implementations

                        // Just reuse to prevent extra RAM, anyhow they'll
                        // get reallocated at the next iteration
                        mixing_config config = {&wolfssl, "wolfssl", fanout};
                        keymix(in, out_a, size, &config);

                        config.mixfunc = &openssl;
                        config.descr   = "openssl";
                        keymix(in, out_b, size, &config);

                        config.mixfunc = &aesni;
                        config.descr   = "aesni";
                        keymix(in, out_c, size, &config);

                        COMPARE(out_a, out_b, size, "WoflSSL != OpenSSL\n");
                        COMPARE(out_a, out_c, size, "WoflSSL != Aes-NI\n");
                        COMPARE(out_b, out_c, size, "OpenSSL != Aes-NI\n");

                        if (err)
                                goto cleanup;
                        printf("  > [ENC OK]\n");
                }
        }

cleanup:
        free(out_a);
        free(out_b);
        free(out_c);
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
