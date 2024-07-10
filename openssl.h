#ifndef OPENSSL_H
#define OPENSSL_H

#include "types.h"
#include <stdlib.h>

int openssl(byte *seed, byte *out, size_t seed_size);

#endif
