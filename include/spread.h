#ifndef SPREAD_H
#define SPREAD_H

#include "types.h"

typedef struct {
        uint8_t thread_id;

        byte *buffer;
        size_t buffer_size;

        byte *buffer_abs;
        size_t buffer_abs_size;

        uint8_t thread_levels;
        uint8_t total_levels;
        uint8_t fanout;
} spread_chunks_args_t;

void spread(byte *buffer, size_t size, uint8_t level, uint8_t fanout);

void spread_chunks(spread_chunks_args_t *args, uint8_t level);

#endif
