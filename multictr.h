#ifndef MULTICTR_H
#define MULTICTR_H

#include "types.h"
#include <stdlib.h>

int multictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro);
int recmultictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro);

#endif
