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
        uint8_t ithr, ethr;
        if (threads == 1) {
                ithr = 1;
                ethr = 1;
        } else if (ISPOWEROF(threads, fanout)) {
                ithr = threads;
                ethr = 1;
        } else if (threads % fanout == 0) {
                // Find highest power of fanout and use that as the internal threads,
                // and the external threads will be the remaining.
                // In this way, we always guarantee that we use at most the
                // number of threads chosen by the user.
                ithr = fanout;
                while (ithr * fanout <= threads)
                        ithr *= fanout;

                ethr = threads - ithr;
        } else {
                ithr = 1;
                ethr = threads;
        }

        *internal_threads = ithr;
        *external_threads = ethr;
}

int stream_encrypt(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads) {
        uint8_t internal_threads, external_threads;

        // First, separate threads into internals and externals correctly,
        // since internals must be a power of fanout
        derive_thread_numbers(&internal_threads, &external_threads, ctx->fanout, threads);

        // Then, we encrypt the input resource in a "streamed" manner:
        // that is, we read `external_threads` groups, each one of size
        // `ctx->key_size`, use encrypt_t on that, and lastly write the result
        // to the output.
        size_t buffer_size = external_threads * ctx->key_size;
        byte *buffer       = malloc(buffer_size);

        uint128_t counter = 0;
        size_t read       = 0;

        do {
                // Read a certain number of bytes
                read = fread(buffer, 1, buffer_size, fin);

                // We have read everything we can, we don't need to encrypt
                // an empty buffer, nor to write anything to the output
                if (read == 0)
                        break;

                encrypt_ex(ctx, buffer, buffer, read, external_threads, internal_threads, counter);

                fwrite(buffer, read, 1, fout);
                counter += external_threads; // We encrypt `external_threads` at a time
        } while (read == buffer_size);

        free(buffer);
        return 0;
}

// Equal to stream_encrypt, but allocates less RAM.
// Essentially, we first call `keymix_ex` and not `encrypt_ex`, so that we can
// read smaller chunks from the file and manually XOR them.
// One thing of note: this code does one extr keymix when the file is an exact
// multiple of external_threads * key_size, because we read after doing the keymix
// and hence we don't check if the file has ended before.
int stream_encrypt2(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads) {
        uint8_t internal_threads, external_threads;

        derive_thread_numbers(&internal_threads, &external_threads, ctx->fanout, threads);

        size_t buffer_size = external_threads * ctx->key_size;
        byte *buffer       = malloc(buffer_size);

        // We use key_size because it is surely a divisor of buffer_size.
        // If it weren't, then we would have to manage cases where we read
        // more than we have keymix-ed, and then use the read data to XOR
        // with others
        size_t fbuf_size = ctx->key_size;
        byte *fbuf       = malloc(fbuf_size);

        uint128_t counter = 0;
        size_t read       = 0;
        do {
                byte *bp = buffer;

                read = fread(fbuf, 1, fbuf_size, fin);
                if (read == 0)
                        goto while_end;

                keymix_ex(ctx, buffer, buffer_size, external_threads, internal_threads, counter);

                // We have to XOR the whole buffe (however, we can break away
                // if we get to the EOF first)
                for (; bp < buffer + buffer_size && read > 0; bp += fbuf_size) {
                        memxor(fbuf, fbuf, bp, read);

                        fwrite(fbuf, read, 1, fout);

                        // Read the next, but only if we havent finished the
                        // buffer, otherwise we do one read too much
                        if (bp + fbuf_size < buffer + buffer_size)
                                read = fread(fbuf, 1, fbuf_size, fin);
                }

                counter += external_threads;
        } while (read == fbuf_size);

while_end:
        free(buffer);
        free(fbuf);
        return 0;
}
