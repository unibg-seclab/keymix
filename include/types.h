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
        FANOUT8 = 8,
        FANOUT10 = 10,
} fanout_t;

#ifndef SIZE_MACRO
// // AES block size (128 bit)
// #define SIZE_MACRO 16

// // SHA3-256 and BLAKE2s block size (256 bit)
// #define SIZE_MACRO 32

// // MixCTR block size (384 bit)
// #define SIZE_MACRO 48

// // SHA3 and BLAKE2B block size (512 bit)
// #define SIZE_MACRO 64

// // SHAKE256 is an extendable output functions (XOF) with an internal state of
// // 1600 bit. The sponge function produces this state by diving the input in
// // rate and capacity. With SHAKE256 the rate is 1088 bit and the capacity
// // 512 bit. So, assuming chunks of 128 bit, we cannot go past a block
// // size of 8 * 128 = 1024 bit
// #define SIZE_MACRO 128

// SHAKE128 is an extendable output functions (XOF) with an internal state of
// 1600 bit. The sponge function produces this state by diving the input in
// rate and capacity. With SHAKE256 the rate is 1344 bit and the capacity
// 256 bit. So, assuming chunks of 128 bit, we cannot go past a block
// size of 10 * 128 = 1280 bit
#define SIZE_MACRO 160
#endif /* SIZE_MACRO */

#endif
