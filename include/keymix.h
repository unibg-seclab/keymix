#ifndef KEYMIX_H_
#define KEYMIX_H_

#include "types.h"

int keymix(byte *seed, byte *out, size_t seed_size, mixing_config *config, uint8_t nof_threads);

#endif // KEYMIX_H_
