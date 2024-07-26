#ifndef KEYMIX_H_
#define KEYMIX_H_

#include "types.h"

int keymix(mixctrpass_impl_t mixctrpass, byte *seed, byte *out, size_t seed_size, uint8_t fanout,
           uint8_t nof_threads);

#endif // KEYMIX_H_
