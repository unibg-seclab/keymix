#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/types.h>

#include "ctx.h"
#include "keymix.h"
#include "log.h"
#include "mix.h"
#include "types.h"
#include "utils.h"

#define MIX_TYPE OPENSSL_MATYAS_MEYER_OSEAS_128
#define PRECISION 2
#define SIZE_1MiB (1024 * 1024)

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

int main() {
        mix_func_t func;
        block_size_t block_size;
        uint8_t chunk_size;
        uint8_t fanout;
        byte *key;
        byte *out;
        size_t key_size;
        uint64_t nof_macros;
        uint8_t levels;
        int err = 0;
        double time;
        double readable_size;

        uint8_t threads[] = {1, 2, 4, 8, 16};
        uint8_t nof_threads;

        printf("[*] Multi-threaded execution of keymix (%s)...\n\n", get_mix_name(MIX_TYPE));

        if (get_mix_func(MIX_TYPE, &func, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing primitive\n");
                exit(EXIT_FAILURE);
        }

        printf("block size:\t%d\n", block_size);
        get_fanouts_from_block_size(block_size, 1, &fanout);
        printf("fanout:\t\t%d\n", fanout);

        key_size = block_size;
        while (key_size < 256 * SIZE_1MiB) {
                key_size *= fanout;
        }
        printf("key size:\t%zu MiB\n", key_size / SIZE_1MiB);
        key = malloc(key_size);
        out = malloc(key_size);
        if (key == NULL || out == NULL) {
                _log(LOG_ERROR, "Cannot allocate memory\n");
                goto cleanup;
        }

        printf("levels:\t\t%d\n\n", 1 + (uint8_t) LOGBASE(key_size / block_size, fanout));

        for (uint8_t t = 0; t < sizeof(threads) / sizeof(uint8_t); t++) {
                printf("[+] with %d threads\n", threads[t]);
                nof_threads = threads[t];

                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);

                double time =
                    MEASURE({ err = keymix(func, key, out, key_size, block_size, fanout, nof_threads); });
                readable_size = (double)key_size / SIZE_1MiB;
                printf("total time:\t%.*lf s\n", PRECISION, time / 1000);
                printf("total size:\t%.*lf MiB\n", PRECISION, readable_size);
                printf("average speed:\t%.*lf MiB/s\n\n", PRECISION, readable_size * 1000 / (time));

                if (err) {
                        printf("Error occured while encrypting");
                        goto cleanup;
                }

                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);
        }

        free(key);
        free(out);

        printf("[*] Single-threaded keymix with varying mixing primitives\n\n");
        for (uint8_t i = 0; i < sizeof(MIX_TYPES) / sizeof(mix_t); i++) {
                printf("[+] %s mixing...\n", get_mix_name(MIX_TYPES[i]));

                err = get_mix_func(MIX_TYPES[i], &func, &block_size);
                if (err) {
                        _log(LOG_ERROR, "No implementation found\n");
                        goto cleanup;
                }

                chunk_size = get_chunk_size(block_size);
                fanout = block_size / chunk_size;

                printf("block size:\t%d\n", block_size);
                printf("fanout:\t\t%d\n", fanout);

                key_size = block_size;
                while (key_size < 256 * SIZE_1MiB) {
                        key_size *= fanout;
                }
                printf("key size:\t%zu MiB\n", key_size / SIZE_1MiB);
                key = malloc(key_size);
                out = malloc(key_size);
                if (key == NULL || out == NULL) {
                        _log(LOG_ERROR, "Cannot allocate memory\n");
                        goto cleanup;
                }

                printf("levels:\t\t%d\n", 1 + (uint8_t) LOGBASE(key_size / block_size, fanout));

                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);

                if (key_size <= block_size * fanout) {
                        print_buffer_hex(key, key_size, "key");
                        print_buffer_hex(out, key_size, "out");
                }

                time = MEASURE({ err = keymix(func, key, out, key_size, block_size, fanout, 1); }); // all layers
                // time = MEASURE({ err = (*func)(key, out, key_size); }); // single layer
                if (err) {
                        printf("Error occured while encrypting");
                        goto cleanup;
                }

                readable_size = (double)key_size / SIZE_1MiB;
                printf("total time:\t%.*lf s\n", PRECISION, time / 1000);
                printf("total size:\t%.*lf MiB\n", PRECISION, readable_size);
                printf("average speed:\t%.*lf MiB/s\n\n", PRECISION, readable_size * 1000 / (time));

                explicit_bzero(key, key_size);
                explicit_bzero(out, key_size);
                free(key);
                free(out);
        }

        return EXIT_SUCCESS;

cleanup:
        free(key);
        free(out);
        return err;
}
