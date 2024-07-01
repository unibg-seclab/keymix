#ifndef AESNI_H
#define AESNI_H

#include "types.h"
#include <assert.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/aes.h>

int aesni(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro);

#endif
