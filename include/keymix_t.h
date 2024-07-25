#ifndef KEYMIX_T_H_
#define KEYMIX_T_H_

#include "types.h"

int keymix_t(byte *seed, size_t seed_size, byte *out, size_t out_size, mixing_config *config,
             uint8_t num_threads, uint8_t internal_threads, uint128_t iv);

int enc(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
        uint8_t num_threads, uint128_t iv);

int enc_ex(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
           uint8_t num_threads, uint8_t internal_threads, uint128_t iv, uint128_t starting_counter);

#endif // KEYMIX_T_H_
