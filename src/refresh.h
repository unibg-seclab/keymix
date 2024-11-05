#include <stdint.h>
#include <stdlib.h>

#include "types.h"

// Use multiple-threads to refresh the initial state of the current keymix
// counter
int multi_threaded_refresh(byte *in, byte *out, size_t size, byte *nonce,
                           uint64_t counter, uint8_t threads);
