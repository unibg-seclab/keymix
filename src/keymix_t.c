#include "keymix_t.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "keymix.h"
#include "log.h"
#include "utils.h"

typedef struct {
        byte *seed;
        byte *in;
        byte *out;
        size_t seed_size;
        size_t in_out_size;
        uint64_t num_seeds;
        mixing_config *config;
        uint128_t iv;
        uint128_t starting_counter;
        uint8_t internal_threads;
        bool encrypt;
} args_t;

int enc(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
        uint8_t num_threads, uint128_t iv) {
        return enc_ex(seed, seed_size, in, out, size, config, num_threads, 1, iv, 0);
}

int enc_ex(byte *seed, size_t seed_size, byte *in, byte *out, size_t size, mixing_config *config,
           uint8_t num_threads, uint8_t internal_threads, uint128_t iv,
           uint128_t starting_counter) {
        // TODO: obtain correct number of internal-external threads
        // return keymix_ex(seed, seed_size, in, out, size, config, num_threads, internal_threads,
        // iv,
        //                  true, starting_counter);
        return 0;
}
