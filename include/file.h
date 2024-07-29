#ifndef FILE_H
#define FILE_H

#include "enc.h"
#include "types.h"
#include <stdio.h>

size_t get_file_size(FILE *fp);

int file_encrypt(FILE *fout, FILE *fin, keymix_ctx_t *ctx, uint8_t threads);

void safe_fclose(FILE *fp);

#endif
