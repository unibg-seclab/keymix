#ifndef KEYMIX_H
#define KEYMIX_H

#include "types.h"

int keymix(mixctrpass_impl_t mixctrpass, byte *in, byte *out, size_t size, uint8_t fanout,
           uint8_t nof_threads);

#endif
