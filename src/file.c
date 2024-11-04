#include "file.h"

#include <string.h>
#include <unistd.h>

#include "enc.h"
#include "utils.h"

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

int stream_encrypt(ctx_t *ctx, FILE *fin, FILE *fout, byte *iv,
                   uint8_t threads) {
        // Then, we encrypt the input resource in a "streamed" manner:
        // that is, we read a buffer of `ctx->key_size` size, use encrypt_t on
        // that, and lastly write the result to the output.
        size_t buffer_size = ctx->key_size;
        byte *buffer       = malloc(buffer_size);

        // Make a copy of the IV before changing its counter part, to avoid
        // unexpected side effects
        byte *tmpiv   = NULL;
        byte *counter = NULL;
        if (iv) {
                tmpiv = malloc(KEYMIX_IV_SIZE);
                memcpy(tmpiv, iv, KEYMIX_IV_SIZE);
                counter = tmpiv + KEYMIX_NONCE_SIZE;
        }

        size_t read = 0;
        do {
                // Read a certain number of bytes
                read = fread(buffer, 1, buffer_size, fin);

                // We have read everything we can, we don't need to encrypt
                // an empty buffer, nor to write anything to the output
                if (read == 0)
                        break;

                encrypt_t(ctx, buffer, buffer, read, tmpiv, threads);

                fwrite(buffer, read, 1, fout);
                ctr64_inc(counter);
        } while (read == buffer_size);

        free(buffer);
        if (iv)
                free(tmpiv);
        return 0;
}

// Equal to stream_encrypt, but allocates less RAM.
// Essentially, we first call `keymix_ex` and not `encrypt_t`, so that we can
// read smaller chunks from the file and manually XOR them.
// One thing of note: this code does one extra keymix when the file is an exact
// multiple of key_size, because we read after doing the keymix and hence we
// don't check if the file has ended before.
int stream_encrypt2(ctx_t *ctx, FILE *fin, FILE *fout, byte *iv,
                    uint8_t threads) {
        size_t buffer_size = ctx->key_size;
        byte *buffer       = malloc(buffer_size);

        // We use key_size because it is surely a divisor of buffer_size.
        // If it weren't, then we would have to manage cases where we read
        // more than we have keymix-ed, and then use the read data to XOR
        // with others
        size_t fbuf_size = ctx->key_size;
        byte *fbuf       = malloc(fbuf_size);

        // Make a copy of the IV before changing its counter part, to avoid
        // unexpected side effects
        byte *tmpiv   = NULL;
        byte *counter = NULL;
        if (iv) {
                tmpiv = malloc(KEYMIX_IV_SIZE);
                memcpy(tmpiv, iv, KEYMIX_IV_SIZE);
                counter = tmpiv + KEYMIX_NONCE_SIZE;
        }

        size_t read   = 0;
        do {
                byte *bp = buffer;

                read = fread(fbuf, 1, fbuf_size, fin);
                if (read == 0)
                        goto while_end;

                keymix_ex(ctx, buffer, buffer_size, tmpiv, threads);

                // We have to XOR the whole buffer (however, we can break away
                // if we get to the EOF first)
                for (; bp < buffer + buffer_size && read > 0; bp += fbuf_size) {
                        memxor(fbuf, fbuf, bp, read);

                        fwrite(fbuf, read, 1, fout);

                        // Read the next, but only if we havent finished the
                        // buffer, otherwise we do one read too much
                        if (bp + fbuf_size < buffer + buffer_size)
                                read = fread(fbuf, 1, fbuf_size, fin);
                }

                ctr64_inc(counter);
        } while (read == fbuf_size);

while_end:
        free(buffer);
        free(fbuf);
        if (iv)
                free(tmpiv);
        return 0;
}
