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
        FANOUT12 = 12,
} fanout_t;

#ifndef SIZE_BLOCK
// AES block size (128 bit)
// #define SIZE_BLOCK 16

// // SHA3-256 and BLAKE2s block size (256 bit)
// #define SIZE_BLOCK 32

// // SHA3 and BLAKE2B block size (512 bit)
// #define SIZE_BLOCK 64

// SHAKE128 and SHAKE256 are extendable output functions (XOF) with an internal
// state of 1600 bit. So, assuming chunks of 128 bit, we cannot go past a block
// size of 12 * 128 = 1536 bit
#define SIZE_BLOCK 192
#endif

// With MixCTR original implementation a macro is composed by 3 AES blocks
#define BLOCKS_PER_MACRO 3

#ifndef SIZE_MACRO
// In most cases equal to the size of the block
// With MixCTR original implementation is equal to SIZE_BLOCK * BLOCKS_PER_MACRO
#define SIZE_MACRO SIZE_BLOCK
#endif

#endif
