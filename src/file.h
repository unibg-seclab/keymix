#ifndef FILE_H
#define FILE_H

#include <stdio.h>

#include "enc.h"
#include "types.h"

// Obtains the size of the stream `fp`.
size_t get_file_size(FILE *fp);

// Encrypts a stream `fin` with the context `ctx` writing the result on `fout`,
// Using `threads` threads.
int stream_encrypt(ctx_t *ctx, FILE *fin, FILE *fout, byte *iv,
                   uint8_t threads);

// Encrypts a stream `fin` with the context `ctx` writing the result on `fout`,
// Using `threads` threads.
// This is an alternative version to `stream_encrypt2`.
int stream_encrypt2(ctx_t *ctx, FILE *fin, FILE *fout, byte *iv,
                    uint8_t threads);

#endif
