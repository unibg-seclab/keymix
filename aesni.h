#ifndef AESNI_H
#define AESNI_H

#include "types.h"
#include <assert.h>
#include <stdlib.h>
#include <wolfssl/wolfcrypt/aes.h>

void aes128enc(byte *data, byte *out, byte *key, size_t blocks);
void aes256enc(byte *data, byte *out, byte *key, size_t blocks);

int aesni(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro);

#endif
