#ifndef TYPES_H
#define TYPES_H

// A single byte.
typedef unsigned char byte;

// A 128-bit (16 B) integer.
// This requires GCC to be used as a compiler.
typedef __uint128_t uint128_t;

// Accepted fanouts by the spread algorithm.
typedef enum {
        FANOUT2 = 2,
        FANOUT3 = 3,
        FANOUT4 = 4,
} fanout_t;

// An AES block size (128 bits)
// #define SIZE_BLOCK 16
// SHA3 block size (512 bit)
#define SIZE_BLOCK 64

// A macro of ours is composed by 3 AES blocks
#define BLOCKS_PER_MACRO 3
// #define SIZE_MACRO 48
#define SIZE_MACRO 64

#endif
