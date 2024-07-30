#ifndef MIXCTR_H
#define MIXCTR_H

#include "types.h"

mixctrpass_impl_t get_mixctr_impl(mixctr_t name);

mixctr_t mixctr_from_str(char *name);

int wolfssl(byte *in, byte *out, size_t size);
int openssl(byte *in, byte *out, size_t size);
int aesni(byte *in, byte *out, size_t size);

#endif
