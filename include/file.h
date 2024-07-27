#ifndef FILE_H
#define FILE_H

#include "types.h"
#include <stdio.h>

size_t get_file_size(FILE *fp);
int paged_storage_write(FILE *fstr_output, FILE *fstr_resource, size_t resource_size, byte *out,
                        size_t seed_size, size_t page_size);

#endif
