#ifndef FILE_H
#define FILE_H

#include "enc.h"
#include "types.h"
#include <stdio.h>

// Obtains the size of the stream `fp`.
size_t get_file_size(FILE *fp);

// Encrypts a stream `fin` with the context `ctx` writing the result on `fout`,
// Using `threads` threads.
int stream_encrypt(FILE *fout, FILE *fin, ctx_t *ctx, uint8_t threads);

// Encrypts a stream `fin` with the context `ctx` writing the result on `fout`,
// Using `threads` threads.
// This is an alternative version to `stream_encrypt2`.
int stream_encrypt2(FILE *fout, FILE *fin, ctx_t *ctx, uint8_t threads);

#endif
