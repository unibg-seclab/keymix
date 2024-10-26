#ifndef SPREAD_H
#define SPREAD_H

#include "mix.h"
#include "types.h"
#include <stdint.h>
#include <stdlib.h>

// Implements the spread algorithm in-place.
void spread(byte *buffer, size_t size, uint8_t level, block_size_t block_size, uint8_t fanout);

// Data needed by the in-place `spread` algorithm.
typedef struct {
        // The (progressive) number of the thread, starting from 0.
        uint8_t thread_id;

        // Total number of threads.
        uint8_t nof_threads;

        // A pointero to the buffer portion on which to operate.
        byte *buffer;
        // The Thread portion size.
        size_t buffer_size;

        // The pointer to the actual beginning of the buffer,
        byte *buffer_abs;
        // The actual size of the whole buffer.
        size_t buffer_abs_size;

        // Block size of the mixing primitive
        block_size_t block_size;

        // The fanout to consider.
        uint8_t fanout;

        // The current level at which to apply the spread.
        uint8_t level;
} spread_chunks_args_t;

// Implements the spread algorithm in-place and can be called by a single
// thread without the need to synchronize.
void spread_chunks(spread_chunks_args_t *args);

// Implements the spread algorithm in-place and can be called by multiple
// threads working on different windows.
void spread_chunks_without_constraints(spread_chunks_args_t *args);

#endif
