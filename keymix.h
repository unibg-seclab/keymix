#ifndef KEYMIX_H
#define KEYMIX_H

#include "types.h"

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config);

int parallel_keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config,
                    unsigned int nof_threads);

#endif
