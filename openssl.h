#ifndef SINGLECTR_OPENSSL_H
#define SINGLECTR_OPENSSL_H

#include "types.h"
#include <stdlib.h>

int openssl(byte *seed, byte *out, size_t seed_size);

#endif
