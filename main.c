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

#define PRECISION 2
#define SIZE_1MiB (1024 * 1024)
#define KEY_SIZE 256 * SIZE_1MiB
#define MIX_TYPE OPENSSL_MATYAS_MEYER_OSEAS_128

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

int run_keymix(size_t desired_key_size, mix_impl_t mix_type, uint8_t nof_threads) {
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

        err = get_mix_func(mix_type, &func, &block_size);
        if (err) {
                _log(LOG_ERROR, "No implementation found\n");
                goto cleanup;
        }

        get_fanouts_from_block_size(block_size, 1, &fanout);

        key_size = block_size;
        while (key_size < desired_key_size) {
                key_size *= fanout;
        }
        
        printf("block size:\t%d\n", block_size);
        printf("fanout:\t\t%d\n", fanout);
        printf("key size:\t%zu MiB\n", key_size / SIZE_1MiB);
        printf("levels:\t\t%d\n", 1 + (uint8_t) LOGBASE(key_size / block_size, fanout));

        key = malloc(key_size);
        out = malloc(key_size);
        if (key == NULL || out == NULL) {
                _log(LOG_ERROR, "Cannot allocate memory\n");
                goto cleanup;
        }

        // Initialize key and keystream buffers
        explicit_bzero(key, key_size);
        explicit_bzero(out, key_size);

        if (key_size <= block_size * fanout) {
                print_buffer_hex(key, key_size, "key");
                print_buffer_hex(out, key_size, "out");
        }

        ctx_t ctx;
        err = ctx_keymix_init(&ctx, mix_type, key, key_size, fanout);
        if (err) {
                _log(LOG_ERROR, "Keymix context initialization exited with %d\n", err);
                goto ctx_cleanup;
        }

        time = MEASURE({ err = keymix_t(&ctx, out, key_size, nof_threads); }); // all layers
        // time = MEASURE({ err = (*func)(key, out, key_size, MIXPASS_DEFAULT_IV); }); // single layer
        if (err) {
                printf("Error occured while encrypting");
                goto ctx_cleanup;
        }

        readable_size = (double)key_size / SIZE_1MiB;
        printf("total time:\t%.*lf s\n", PRECISION, time / 1000);
        printf("total size:\t%.*lf MiB\n", PRECISION, readable_size);
        printf("average speed:\t%.*lf MiB/s\n\n", PRECISION, readable_size * 1000 / (time));

ctx_cleanup:
        ctx_free(&ctx);
cleanup:
        free(key);
        free(out);
        return err;
}


int main() {
        uint8_t threads[] = {1, 2, 4, 8, 16};

        printf("[*] Multi-threaded execution of keymix (%s)...\n\n", get_mix_name(MIX_TYPE));
        for (uint8_t t = 0; t < sizeof(threads) / sizeof(uint8_t); t++) {
                printf("[+] with %d threads\n", threads[t]);
                run_keymix(KEY_SIZE, MIX_TYPE, threads[t]);
        }

        printf("[*] Single-threaded keymix with varying mixing implementations\n\n");
        for (uint8_t i = 0; i < sizeof(MIX_TYPES) / sizeof(mix_impl_t); i++) {
                printf("[+] %s mixing...\n", get_mix_name(MIX_TYPES[i]));
                run_keymix(KEY_SIZE, MIX_TYPES[i], 1);
        }

        return EXIT_SUCCESS;
}
