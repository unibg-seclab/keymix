#ifndef KEYMIX_SEQ_H
#define KEYMIX_SEQ_H

#include "types.h"

#include <stdio.h>

int keymix_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource, size_t page_size,
               size_t resource_size, byte *secret, size_t secret_size);

int keymix_inter_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                     size_t page_size, size_t resource_size, byte *secret, size_t secret_size);

int keymix_intra_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                     size_t page_size, size_t resource_size, byte *secret, size_t secret_size);

int keymix_inter_intra_seq(struct arguments *config, FILE *fstr_output, FILE *fstr_resource,
                           size_t page_size, size_t resource_size, byte *secret,
                           size_t secret_size);

#endif
