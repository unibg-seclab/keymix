#ifndef AESNI_H
#define AESNI_H

#include "types.h"
#include <stdlib.h>

void aes128enc(byte *data, byte *out, byte *key, size_t blocks);
void aes256enc(byte *data, byte *out, byte *key, size_t blocks);

#endif
