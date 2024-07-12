#ifndef KEYMIX_T_H
#define KEYMIX_T_H

#include "types.h"

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             int num_threads, int internal_threads, __uint128_t iv);

#endif
