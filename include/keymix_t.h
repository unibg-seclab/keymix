#ifndef KEYMIX_T_H
#define KEYMIX_T_H

#include "types.h"

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             uint8_t num_threads, uint8_t internal_threads, uint128_t iv);

#endif
