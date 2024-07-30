#ifndef CONFIG_H
#define CONFIG_H

// An AES block size (128 bits)
#define SIZE_BLOCK 16

// A macro of ours is composed by 3 AES blocks
#define BLOCKS_PER_MACRO 3
#define SIZE_MACRO 48

// Set global log level
#define LOG_LEVEL LOG_INFO

// Use if you want to disable logging altogether, will remove code if compiled
// with optimizations, only setting the log level doesn't remove the function
// call.
// Useful for testing.
#define DISABLE_LOG 0

// Use to enable debug-time checks (e.g., some assertions)
#define DEBUG 0

#endif // CONFIG_H
