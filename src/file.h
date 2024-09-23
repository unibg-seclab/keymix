#ifndef FILE_H
#define FILE_H

#include "enc.h"
#include "types.h"
#include <stdio.h>

size_t get_file_size(FILE *fp);

int stream_encrypt(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads, uint8_t blocks);
int stream_encrypt2(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads, uint8_t blocks);

void safe_fclose(FILE *fp);

#endif
