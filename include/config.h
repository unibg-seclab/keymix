#ifndef CONFIG_H
#define CONFIG_H

// errors
#define ERR_ENC 1

// configuratins

// sizes
#define SIZE_BLOCK 16
#define BLOCKS_PER_MACRO 3
#define SIZE_MACRO (BLOCKS_PER_MACRO * SIZE_BLOCK)

// Enable or disable debug-time checks
#define DEBUG 0

#endif
