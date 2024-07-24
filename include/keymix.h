#ifndef KEYMIX_H
#define KEYMIX_H

#include "types.h"

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config, uint32_t nof_threads);

#endif
