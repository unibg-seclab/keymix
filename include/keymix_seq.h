#ifndef KEYMIX_SEQ_H_
#define KEYMIX_SEQ_H_

#include <stdio.h>

#include "types.h"

int keymix_seq(cli_args_t *config, FILE *fstr_output, FILE *fstr_resource, size_t page_size,
               size_t resource_size, byte *secret, size_t secret_size);

int keymix_inter_seq(cli_args_t *config, FILE *fstr_output, FILE *fstr_resource, size_t page_size,
                     size_t resource_size, byte *secret, size_t secret_size);

int keymix_intra_seq(cli_args_t *config, FILE *fstr_output, FILE *fstr_resource, size_t page_size,
                     size_t resource_size, byte *secret, size_t secret_size);

int keymix_inter_intra_seq(cli_args_t *config, FILE *fstr_output, FILE *fstr_resource,
                           size_t page_size, size_t resource_size, byte *secret,
                           size_t secret_size);

#endif // KEYMIX_SEQ_H_
