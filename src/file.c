#include "file.h"

#include "utils.h"
#include <unistd.h>

size_t get_file_size(FILE *fp) {
        if (fp == NULL)
                return 0;

        if (fseek(fp, 0, SEEK_END) < 0)
                return 0;

        long res = ftell(fp);
        if (res < 0) {
                fprintf(stderr, "Cannot get size of file\n");
                return 0;
        }

        if (fseek(fp, 0, SEEK_SET) < 0)
                return 0;

        return (size_t)res;
}

void safe_fclose(FILE *fp) {
        if (fp != NULL)
                fclose(fp);
}

void derive_thread_numbers(uint8_t *internal_threads, uint8_t *external_threads, uint8_t fanout,
                           uint8_t threads) {
        if (threads == 1) {
                *internal_threads = 1;
                *external_threads = 1;
        } else if (ISPOWEROF(threads, fanout)) {
                *internal_threads = threads;
                *external_threads = 1;
        } else if (threads % fanout == 0) {
                // Find highest power of fanout and use that as the internal threads,
                // and the external threads will be the remaining.
                // In this way, we always guarantee that we use at most the
                // number of threads chosen by the user.
                *internal_threads = fanout;
                while ((*internal_threads) * fanout <= threads)
                        *internal_threads *= fanout;

                *external_threads = threads - *internal_threads;
        } else {
                *internal_threads = 1;
                *external_threads = threads;
        }
}

int file_encrypt(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads) {
        uint8_t internal_threads, external_threads;

        // First, separate threads into internals and externals correctly,
        // since internals must be a power of fanout
        derive_thread_numbers(&internal_threads, &external_threads, ctx->fanout, threads);

        // Then, we encrypt the input resource in a "streamed" manner:
        // that is, we read `external_threads` groups, each one of size
        // `ctx->key_size`, use encrypt_t on that, and lastly write the result
        // to the output.

        // However, note that the resource could be not a multiple of key_size,
        // hence we have to read the MINIMUM between `external_threads * key_size`
        // and the remaining resource, which is why we track input_size

        size_t buffer_size    = external_threads * ctx->key_size;
        size_t remaining_size = get_file_size(fin);
        byte *in_buffer       = malloc(buffer_size);
        byte *out_buffer      = malloc(buffer_size);

        uint128_t counter = 0;

        while (remaining_size > 0) {
                size_t size_to_read = MIN(remaining_size, buffer_size);

                fread(in_buffer, size_to_read, 1, fin);

                encrypt_ex(ctx, in_buffer, out_buffer, size_to_read, external_threads,
                           internal_threads, counter);

                fwrite(out_buffer, size_to_read, 1, fout);

                remaining_size -= size_to_read;
                counter += external_threads; // We encrypt `external_threads` at a time
        }

        free(in_buffer);
        return 0;
}
