#ifndef CONFIG_H
#define CONFIG_H

// errors
#define ERR_ENC 1
#define ERR_ARGP 2
#define ERR_FREAD 3
#define ERR_FWRITE 4
#define ERR_RLIMIT 5

// sizes
#define SIZE_BLOCK 16
#define BLOCKS_PER_MACRO 3
#define SIZE_MACRO 48

// enable or disable debug-time checks
#define DEBUG 1

// threads
#define MAX_THREAS 128
#define MIN_THREAS 1

#endif
