#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

// sizes
#define TERMINAL_SIZE 64
#define SIZE_MACRO 48
#define SIZE_KB 1024
#define SIZE_1MiB (1024 * SIZE_KB)
#define SIZE_1GiB (1024 * SIZE_1MiB) // current limit

// errors
#define ERR_ENC 1

// configuratins
#define SILENCE 1

// types
#define byte unsigned char

byte *TMP_BUF;

struct mixing_config {
        int (*mixfunc)(byte *, byte *, size_t, unsigned int);
        char *descr;
        unsigned int blocks_per_macro; // number of 128-bit blocks in each macro
        unsigned int diff_factor;      // diffusion factor (swap functio): 3 (128 bits), 4
                                       // (96 bits), 6 (64 bits), 12 (32 bits)
};

void memxor(byte *dst, byte *src, size_t n) {
        for (unsigned int i = 0; i < n; i++) {
                dst[i] ^= src[i];
        }
}

void *checked_malloc(size_t size) {
        byte *buf = malloc(size);
        if (buf == NULL) {
                printf("(!) Error occured while allocating memory\n");
                free(buf);
                exit(1);
        }
        return buf;
}

void set_zero(byte *buf, size_t size) {
        for (unsigned int i = 0; i < size; i++) {
                buf[i] = 0;
        }
}

unsigned char *generate_random_bytestream(int num_bytes) {

        byte *buf   = malloc(num_bytes);
        int success = RAND_bytes(buf, num_bytes);
        if (!success) {
                free(buf);
                exit(1);
        }

        return buf;
}

void print_buffer_hex(byte *buf, size_t size, char *descr) {
        printf("%s\n", descr);
        for (size_t i = 0; i < size; i++) {
                if (i % 16 == 0) {
                        printf("|");
                }
                printf("%02x", buf[i]);
        }
        printf("|\n");
}

unsigned long get_current_time_millis() {
        struct timeval tp;
        gettimeofday(&tp, NULL);
        unsigned long current_time_millisec = tp.tv_sec * 1000 + tp.tv_usec / 1000;
        return current_time_millisec;
}

unsigned long print_time_delta(long previous_time_millis, char *descr) {
        unsigned long current_time_millisec = get_current_time_millis();
        if (!SILENCE)
                printf("%s: %ld", descr, current_time_millisec - previous_time_millis);
        return current_time_millisec;
}

int singlectr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {

        if (blocks_per_macro != 3) {
                goto err_enc;
        }
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                printf("AesInit returned: %d\n", err);
                goto err_enc;
        }
        unsigned int ROUNDS, KEY_OFFSET, IV_OFFSET;
        ROUNDS    = seed_size / (AES_BLOCK_SIZE * blocks_per_macro);
        IV_OFFSET = 2 * AES_BLOCK_SIZE;
        for (unsigned int r = 0; r < ROUNDS; r++) {
                KEY_OFFSET = r * blocks_per_macro * AES_BLOCK_SIZE;
                err =
                    wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL, AES_ENCRYPTION);
                if (err != 0) {
                        printf("AesSetKey returned: %d\n", err);
                        goto err_enc;
                }
                for (unsigned short b = 0; b < blocks_per_macro; b++) {
                        err = wc_AesEncryptDirect(&aes, out + KEY_OFFSET + b * AES_BLOCK_SIZE,
                                                  seed + KEY_OFFSET + IV_OFFSET);
                        if (err != 0) {
                                printf("AesEncryptDirect returned: %d\n", err);
                                goto err_enc;
                        }
                        seed[KEY_OFFSET + IV_OFFSET] += 1;
                }
        }
        // remember that outside of this function the result is saved into (byte
        // *out)
        wc_AesFree(&aes);
        return 0;
err_enc:
        wc_AesFree(&aes);
        return ERR_ENC;
}

int multictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {

        // current max ctr len = 2^8-1
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                printf("AesInit returned: %d\n", err);
                goto err_enc;
        }
        unsigned int MACRO_OFFSET;
        for (unsigned int u = 0; u < seed_size / (AES_BLOCK_SIZE * blocks_per_macro); u++) {
                MACRO_OFFSET = u * blocks_per_macro * AES_BLOCK_SIZE;
                unsigned int KEY_OFFSET, IV_OFFSET;
                IV_OFFSET = 2 * AES_BLOCK_SIZE;
                for (unsigned int tblock = 0; tblock < blocks_per_macro / 3; tblock++) {
                        // offset of a new key
                        KEY_OFFSET = MACRO_OFFSET + tblock * 3 * AES_BLOCK_SIZE;
                        err        = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL,
                                                  AES_ENCRYPTION);
                        if (err != 0) {
                                printf("AesSetKey returned: %d\n", err);
                                goto err_enc;
                        }
                        for (unsigned short b = 0; b < blocks_per_macro; b++) {
                                err = wc_AesEncryptDirect(&aes, TMP_BUF,
                                                          seed + KEY_OFFSET + IV_OFFSET);
                                if (err != 0) {
                                        printf("AesEncryptDirect returned: %d\n", err);
                                        goto err_enc;
                                }
                                seed[KEY_OFFSET + IV_OFFSET] += 1;
                        }
                        if (tblock == 0) {
                                // copy
                                memcpy(&out[MACRO_OFFSET], TMP_BUF,
                                       blocks_per_macro * AES_BLOCK_SIZE);
                        } else {
                                // xor
                                memxor(&out[MACRO_OFFSET], TMP_BUF,
                                       blocks_per_macro * AES_BLOCK_SIZE);
                        }
                }
        }
        // remember that outside of this function the result is saved into (byte
        // *out)
        wc_AesFree(&aes);
        return 0;
err_enc:
        wc_AesFree(&aes);
        return ERR_ENC;
}

int recmultictr(byte *seed, byte *out, size_t seed_size, unsigned int blocks_per_macro) {
        Aes aes;
        int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (err != 0) {
                printf("AesInit returned: %d\n", err);
                goto err_enc;
        }
        unsigned int MACRO_OFFSET;
        unsigned int IV_OFFSET = 2 * AES_BLOCK_SIZE;
        unsigned int ROUNDS    = seed_size / (AES_BLOCK_SIZE * blocks_per_macro);
        for (unsigned int r = 0; r < ROUNDS; r++) {
                MACRO_OFFSET = r * blocks_per_macro * AES_BLOCK_SIZE;
                unsigned int KEY_OFFSET;
                for (unsigned int tblock = 0; tblock < blocks_per_macro / 3; tblock++) {
                        // offset of a new key
                        KEY_OFFSET = MACRO_OFFSET + tblock * 3 * AES_BLOCK_SIZE;
                        err        = wc_AesSetKey(&aes, &seed[KEY_OFFSET], 2 * AES_BLOCK_SIZE, NULL,
                                                  AES_ENCRYPTION);
                        if (err != 0) {
                                printf("AesSetKey returned: %d\n", err);
                                goto err_enc;
                        }
                        for (unsigned short b = 0; b < (1 + tblock) * 3; b++) {
                                err = wc_AesEncryptDirect(&aes, TMP_BUF,
                                                          seed + KEY_OFFSET + IV_OFFSET);
                                if (err != 0) {
                                        printf("AesEncryptDirect returned: %d\n", err);
                                        goto err_enc;
                                }
                                seed[KEY_OFFSET + IV_OFFSET] += 1;
                        }
                        if (tblock == 0) {
                                // copy
                                memcpy(&seed[MACRO_OFFSET], TMP_BUF,
                                       (1 + tblock) * 3 * AES_BLOCK_SIZE);
                        } else {
                                // xor
                                memxor(&seed[MACRO_OFFSET], TMP_BUF,
                                       (1 + tblock) * 3 * AES_BLOCK_SIZE);
                        }
                }
        }
        // remember that outside of this function the result is saved into (byte
        // *seed)
        wc_AesFree(&aes);
        return 0;
err_enc:
        wc_AesFree(&aes);
        return ERR_ENC;
}

void swap_seed(byte *out, byte *in, size_t in_size, unsigned int level, unsigned int diff_factor) {

        unsigned long dist = 1;
        for (unsigned int i = 0; i <= level; i++) {
                dist *= diff_factor;
        }

        unsigned int spos;  // slab position
        unsigned int bpos;  // block position
        unsigned int nbpos; // new block position

        for (unsigned int slab = 0; slab < in_size / (AES_BLOCK_SIZE * diff_factor); slab++) {
                spos = slab * AES_BLOCK_SIZE * diff_factor;
                // 1st block never moves
                for (unsigned int block = 1; block < diff_factor; block++) {
                        bpos = (unsigned int)slab + block * AES_BLOCK_SIZE;
                        nbpos =
                            (unsigned int)(((unsigned long)bpos + AES_BLOCK_SIZE * block * dist) &
                                           in_size);
                        // copy the block to the new position
                        memcpy(out + nbpos, in + bpos, (size_t)(SIZE_MACRO / diff_factor));
                }
        }
}

int mix(byte *seed, byte *out, size_t seed_size, struct mixing_config config) {
        unsigned int nof_macros =
            (unsigned int)((seed_size / AES_BLOCK_SIZE) / config.blocks_per_macro);
        unsigned int levels = 1 + (unsigned int)(log10(nof_macros) / log10(config.diff_factor));
        printf("nof_macros:\t\t%d\n", nof_macros);
        printf("levels:\t\t\t%d\n", levels);
        printf("%s mixing...\n", config.descr);
        int err;
        for (unsigned int level = 0; level < levels; level++) {
                unsigned long current_time_millis = get_current_time_millis();
                if (!SILENCE)
                        printf("level %d, ", level);
                err = (*(config.mixfunc))(seed, out, seed_size, config.blocks_per_macro);
                if (err != 0) {
                        goto err_enc;
                }
                current_time_millis = print_time_delta(current_time_millis, "mixed in [ms]");
                // no swap at the last level
                if (levels - 1 != level) {
                        if (config.mixfunc == &recmultictr) {
                                // seed -> seed
                                swap_seed(seed, seed, seed_size, level, config.diff_factor);
                        } else {
                                // out -> seed
                                swap_seed(seed, out, seed_size, level, config.diff_factor);
                        }
                        current_time_millis =
                            print_time_delta(current_time_millis, " swapped in [ms]");
                }
                if (!SILENCE)
                        printf("\n");
        }
        // remember at that at the end of this function the result is saved into
        // (byte *seed)
        return 0;
err_enc:
        return err;
}

int mix_wrapper(byte *seed, byte *out, size_t seed_size, struct mixing_config config) {

        TMP_BUF = checked_malloc(AES_BLOCK_SIZE * config.blocks_per_macro);
        printf("blocks_per_macro:\t%d\n", config.blocks_per_macro);
        printf("diff_factor:\t\t%d\n", config.diff_factor);

        int err = mix(seed, out, seed_size, config);
        if (err != 0) {
                printf("Encryption error\n");
                goto err_enc;
        }
        set_zero(TMP_BUF, AES_BLOCK_SIZE * config.blocks_per_macro);
        free(TMP_BUF);
        set_zero(out, seed_size);
        return 0;
err_enc:
        set_zero(TMP_BUF, AES_BLOCK_SIZE * config.blocks_per_macro);
        free(TMP_BUF);
        set_zero(out, seed_size);
        return ERR_ENC;
}

int main() {

        // todo: rewrite code to test different encryption suites
        // todo: write on a real file
        // todo: recover and check correct parameters
        // todo: apply davies-meyer
        // todo: apply the seed to a file
        // todo: apply the seed at T, T+1, T+2...
        // todo: single-sweep ctr (or rewrite first block) to change seed
        // todo: handle secondary keys (redis?)
        // todo: introduce parallelization as discussed

        // todo: replace usingned int with something else to handle
        // very large seeds (>1GiB)

        //	size_t seed_size = 8503056;
        //	size_t seed_size = 229582512;
        size_t seed_size = 688747536; // in bytes

        byte *seed = checked_malloc(seed_size);
        byte *out  = checked_malloc(seed_size);

        // {function_name, descr, blocks_per_macro, diff_factor}
        struct mixing_config configs[] = {
            {&multictr, "multictr", 9, 9},
            {&recmultictr, "recmultictr", 9, 9},
            {&singlectr, "singlectr", 3, 3},
        };

        unsigned int err = 0;
        for (unsigned int i = 0; i < sizeof(configs) / sizeof(struct mixing_config); i++) {
                printf("zeroing memory...\n");
                set_zero(seed, seed_size);
                set_zero(out, seed_size);
                unsigned long start_time_millis = get_current_time_millis();
                if (seed_size <= 3 * AES_BLOCK_SIZE * 3) {
                        print_buffer_hex(seed, seed_size, "seed");
                        print_buffer_hex(out, seed_size, "out");
                }
                err = mix_wrapper(seed, out, seed_size, configs[i]);
                if (err != 0) {
                        printf("Error occured while encrypting");
                        goto clean;
                }
                unsigned long end_time_millis = get_current_time_millis();
                unsigned short precision      = 2;
                double readable_size          = (double)seed_size / SIZE_1MiB;
                printf("total time [s]:\t\t%.*lf\n", precision,
                       (double)(end_time_millis - start_time_millis) / 1000);
                printf("total size [MiB]:\t%.*lf\n", precision, readable_size);
                printf("avg. speed [MiB/s]:\t%.*lf\n", precision,
                       readable_size * 1000 / (end_time_millis - start_time_millis));
                printf("====\n");
        }

clean:
        set_zero(seed, seed_size);
        free(seed);
        free(out);
        return err;
}
