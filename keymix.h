#ifndef PARALLEL_KEYMIX_H
#define PARALLEL_KEYMIX_H

#include "types.h"
#include <stdlib.h>

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config);

int parallel_keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config,
                    unsigned int nof_threads);

#endif
