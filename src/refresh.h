#include <stdint.h>
#include <stdlib.h>

#include "types.h"

typedef struct {
        uint8_t id;
        byte *in;
        byte *out;
        size_t size;
        byte *iv;
        uint64_t counter;
} thr_refresh_t;

// Use multiple-threads to refresh the initial state of the current keymix
// counter
int multi_threaded_refresh(byte *in, byte *out, size_t size, byte *iv,
                           uint64_t counter, uint8_t threads);
