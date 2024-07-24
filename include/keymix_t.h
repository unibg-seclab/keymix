#ifndef KEYMIX_T_H
#define KEYMIX_T_H

#include "types.h"

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             unsigned int num_threads, unsigned int internal_threads, uint128_t iv);

#endif
