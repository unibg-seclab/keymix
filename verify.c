#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "enc.h"
#include "keymix.h"
#include "log.h"
#include "mix.h"
#include "spread.h"
#include "types.h"
#include "utils.h"

#define NUM_OF_FANOUTS 3

#define MIN_LEVEL 1
#define MAX_LEVEL 5

#define COMPARE(a, b, size, ...)                                                                   \
        ({                                                                                         \
                int _err = 0;                                                                      \
                if (memcmp(a, b, size)) {                                                          \
                        _log(LOG_INFO, __VA_ARGS__);                                               \
                        _err = 1;                                                                  \
                }                                                                                  \
                _err;                                                                              \
        })

byte *setup(size_t size, bool random) {
        byte *data = (byte *)malloc(size);
        for (size_t i = 0; i < size; i++) {
                data[i] = random ? (rand() % 256) : 0;
        }
        return data;
}

inline double MiB(size_t size) { return (double)size / 1024 / 1024; }

void *_run_thr(void *arg) {
        spread((spread_args_t *)arg);
        return NULL;
}

void emulate_spread(byte *buffer, size_t size, uint8_t level, block_size_t block_size,
                           uint8_t fanout, uint8_t nof_threads) {
        assert(size % block_size == 0);

        if (nof_threads > (size / block_size))
                nof_threads = fanout;

        pthread_t threads[nof_threads];
        spread_args_t thread_args[nof_threads];
        size_t thread_chunk_size;
        uint64_t tot_macros;
        uint64_t macros;
        byte *offset;

        tot_macros = size / block_size;
        offset = buffer;

        for (uint8_t t = 0; t < nof_threads; t++) {
                spread_args_t *arg = thread_args + t;

                macros = tot_macros / nof_threads + (t < tot_macros % nof_threads);
                thread_chunk_size = block_size * macros;

                arg->thread_id       = t;
                arg->nof_threads     = nof_threads;
                arg->buffer          = offset;
                arg->buffer_abs      = buffer;
                arg->buffer_abs_size = size;
                arg->buffer_size     = thread_chunk_size;
                arg->fanout          = fanout;
                arg->level           = level;
                arg->block_size      = block_size;

                pthread_create(&threads[t], NULL, _run_thr, arg);

                offset += thread_chunk_size;
        }

        for (uint8_t t = 0; t < nof_threads; t++) {
                pthread_join(threads[t], NULL);
        }
}

// Verify equivalence of the shuffling operations for mixing a key of size
// fanout^level macro blocks with a varying number of threads.
int verify_shuffles_with_varying_threads(block_size_t block_size, size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * block_size;

        _log(LOG_INFO, "> Verifying that shuffles AT level %zu are thread-independent (%.2f MiB)\n",
             level, MiB(size));

        byte *in = setup(size, true);

        byte *out1 = setup(size, false);
        byte *out2 = setup(size, false);

        // The following functions work inplace. So to avoid overwriting the input we copy it
        memcpy(out1, in, size);

        int err = 0;
        emulate_spread(out1, size, level, block_size, fanout, 1);
        for (int nof_threads = 2; nof_threads < fanout; nof_threads++) {
                memcpy(out2, in, size);
                emulate_spread(out2, size, level, block_size, fanout, nof_threads);
                err += COMPARE(out1, out2, size,
                               "1 thr (spread inplace) != %zu thr (spread chunks inplace)\n", fanout);
                if (err)
                        return err;
        }

        free(in);
        free(out1);
        free(out2);

        return 0;
}

// Verify the equivalence of the results when using different encryption and
// hash libraries
int verify_keymix(block_size_t block_size, size_t fanout, uint8_t level) {
        size_t size = (size_t)pow(fanout, level) * block_size;

        _log(LOG_INFO, "> Verifying keymix mix-independence for size %.2f MiB\n", MiB(size));

        byte *in     = setup(size, true);
        byte *out[2] = { setup(size, false), setup(size, false) };

        mix_impl_t groups[2][2];
        mix_func_t funcs[2];
        block_size_t block_sizes[2];
        int nof_groups = 0;

        switch (block_size) {
        case BLOCK_SIZE_AES:
                nof_groups = 2;
                groups[0][0] = OPENSSL_DAVIES_MEYER_128;
                groups[0][1] = WOLFCRYPT_DAVIES_MEYER_128;
                groups[1][0] = OPENSSL_MATYAS_MEYER_OSEAS_128;
                groups[1][1] = WOLFCRYPT_MATYAS_MEYER_OSEAS_128;
                break;
        case BLOCK_SIZE_SHA3_256:
                nof_groups = 2;
                groups[0][0] = OPENSSL_SHA3_256;
                groups[0][1] = WOLFCRYPT_SHA3_256;
                groups[1][0] = OPENSSL_BLAKE2S;
                groups[1][1] = WOLFCRYPT_BLAKE2S;
                break;
        case BLOCK_SIZE_MIXCTR:
                nof_groups = 2;
                groups[0][0] = AESNI_MIXCTR;
                groups[0][1] = OPENSSL_MIXCTR;
                groups[1][0] = OPENSSL_MIXCTR;
                groups[1][1] = WOLFSSL_MIXCTR;
                break;
        case BLOCK_SIZE_SHA3_512:
                nof_groups = 2;
                groups[0][0] = OPENSSL_SHA3_512;
                groups[0][1] = WOLFCRYPT_SHA3_512;
                groups[1][0] = OPENSSL_BLAKE2B;
                groups[1][1] = WOLFCRYPT_BLAKE2B;
                break;
        case BLOCK_SIZE_SHAKE256:
                nof_groups = 1;
                groups[0][0] = OPENSSL_SHAKE256;
                groups[0][1] = WOLFCRYPT_SHAKE256;
                break;
        case BLOCK_SIZE_SHAKE128:
                nof_groups = 1;
                groups[0][0] = OPENSSL_SHAKE128;
                groups[0][1] = WOLFCRYPT_SHAKE128;
                break;
        }

        int err = 0;
        ctx_t ctx;
        for (int g = 0; g < nof_groups; g++) {
                err = ctx_keymix_init(&ctx, groups[g][0], in, size, fanout);
                if (err) {
                        _log(LOG_ERROR, "Keymix context initialization exited with %d\n", err);
                        exit(EXIT_FAILURE);
                }
                keymix(&ctx, in, out[0], size, 1);
                ctx_free(&ctx);

                err = ctx_keymix_init(&ctx, groups[g][1], in, size, fanout);
                if (err) {
                        _log(LOG_ERROR, "Keymix context initialization exited with %d\n", err);
                        exit(EXIT_FAILURE);
                }
                keymix(&ctx, in, out[1], size, 1);
                ctx_free(&ctx);

                char *error_msg = (char *) malloc(80 * sizeof(char));
                sprintf(error_msg, "%s != %s\n", get_mix_name(groups[g][0]), get_mix_name(groups[g][1]));
                err += COMPARE(out[0], out[1], size, error_msg);
        }

        free(in);
        free(out[0]);
        free(out[1]);

        return err;
}

// Verify the equivalence of the results when using single-threaded and
// multi-threaded encryption with a varying number of threads
int verify_multithreaded_keymix(mix_impl_t mix_type, size_t fanout, uint8_t level) {
        mix_func_t mix;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        size_t size = (size_t)pow(fanout, level) * block_size;

        _log(LOG_INFO, "> Verifying keymix threading-independence for size %.2f MiB\n", MiB(size));

        byte *in     = setup(size, true);
        byte *out1   = setup(size, false);
        byte *outt   = setup(size, false);

        ctx_t ctx;
        int err = 0;
        err = ctx_keymix_init(&ctx, mix_type, in, size, fanout);
        if (err) {
                _log(LOG_ERROR, "Keymix context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }

        keymix(&ctx, in, out1, size, 1);
        for (int nof_threads = 2; nof_threads < fanout; nof_threads++) {
                keymix(&ctx, in, outt, size, nof_threads);
                err += COMPARE(out1, outt, size, "Keymix (1) != Keymix (%d)\n", nof_threads);
                if (err)
                        return err;
        }

        ctx_free(&ctx);

        free(in);
        free(out1);
        free(outt);

        return 0;
}

int verify_keymix_t(mix_impl_t mix_type, size_t fanout, uint8_t level) {
        mix_func_t mix;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        size_t size = (size_t)pow(fanout, level) * block_size;

        _log(LOG_INFO, "> Verifying keymix-t equivalence for size %.2f MiB\n", MiB(size));

        int  err         = 0;
        byte *in         = setup(size, true);
        byte *out_simple = setup(size, false);
        byte *out1       = setup(size, false);
        byte *out2_thr1  = setup(2 * size, 0);
        byte *out2_thr2  = setup(2 * size, 0);
        byte *out3_thr1  = setup(3 * size, 0);
        byte *out3_thr2  = setup(3 * size, 0);

        uint8_t internal_threads = 1;

        ctx_t ctx;
        err = ctx_keymix_init(&ctx, mix_type, in, size, fanout);
        if (err) {
                _log(LOG_ERROR, "Keymix context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }

        keymix(&ctx, in, out_simple, size, 1);
        keymix_t(&ctx, out1, size, 1, internal_threads);

        keymix_t(&ctx, out2_thr1, 2 * size, 1, internal_threads);
        keymix_t(&ctx, out2_thr2, 2 * size, 2, internal_threads);
        keymix_t(&ctx, out3_thr1, 3 * size, 1, internal_threads);
        keymix_t(&ctx, out3_thr2, 3 * size, 2, internal_threads);

        ctx_free(&ctx);

        err += COMPARE(out_simple, out1, size, "Keymix T (x1, 1thr) != Keymix\n");
        err += COMPARE(out2_thr1, out2_thr2, size, "Keymix T (x2, 1thr) != Keymix T (x2, 2thr)\n");
        err += COMPARE(out3_thr1, out3_thr2, size, "Keymix T (x3, 1thr) != Keymix T (x3, 2thr)\n");

        free(in);
        free(out_simple);
        free(out1);
        free(out2_thr1);
        free(out2_thr2);
        free(out3_thr1);
        free(out3_thr2);

        return err;
}

int verify_enc(enc_mode_t enc_mode, mix_impl_t mix_type, mix_impl_t one_way_type, size_t fanout,
               uint8_t level) {
        mix_func_t mix;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        size_t key_size      = (size_t)pow(fanout, level) * block_size;
        size_t resource_size = (rand() % 5) * key_size + (rand() % key_size);

        _log(LOG_INFO, "> Verifying encryption for key size %.2f MiB\n", MiB(key_size));

        byte iv[KEYMIX_IV_SIZE] = {rand()};

        int err   = 0;
        byte *key = setup(key_size, true);
        byte *in  = setup(resource_size, true);

        byte *out1 = setup(resource_size, false);
        byte *out2 = setup(resource_size, false);
        byte *out3 = setup(resource_size, false);

        ctx_t ctx;
        err = ctx_encrypt_init(&ctx, enc_mode, mix_type, one_way_type, key, key_size, iv, fanout);
        if (err) {
                _log(LOG_ERROR, "Encryption context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }

        encrypt(&ctx, in, out1, resource_size);
        // Exclude OFB encryption mode from tests with external threads, since
        // they are not supported
        if (enc_mode == ENC_MODE_CTR || enc_mode == ENC_MODE_CTR_OPT) {
                encrypt_t(&ctx, in, out2, resource_size, 2, 1);
                encrypt_t(&ctx, in, out3, resource_size, 3, 1);

                err += COMPARE(out1, out2, resource_size, "Encrypt != Encrypt (2thr)\n");
                err += COMPARE(out1, out3, resource_size, "Encrypt != Encrypt (3thr)\n");
                err += COMPARE(out2, out3, resource_size, "Encrypt (2thr) != Encrypt (3thr)\n");
        }

        // Momentarily exclude optimized CTR mode from tests with internal
        // threads
        if (enc_mode != ENC_MODE_CTR_OPT) {
                encrypt_t(&ctx, in, out2, resource_size, 1, fanout);
                encrypt_t(&ctx, in, out3, resource_size, 1, fanout * fanout);
                err += COMPARE(out1, out2, resource_size, "Encrypt != Encrypt (%d int-thr)\n", fanout);
                err += COMPARE(out1, out3, resource_size, "Encrypt != Encrypt (%d int-thr)\n",
                        fanout * fanout);
                err += COMPARE(out2, out3, resource_size, "Encrypt (%d int-thr) != Encrypt (%d int-thr)\n",
                        fanout, fanout * fanout);
        }

        free(key);
        free(out1);
        free(out2);
        free(out3);
        return err;
}

int verify_enc_ctr_modes(mix_impl_t mix_type, mix_impl_t one_way_type, size_t fanout,
                         uint8_t level) {
        mix_func_t mix;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        size_t key_size      = (size_t)pow(fanout, level) * block_size;
        size_t resource_size = (rand() % 5) * key_size + (rand() % key_size);

        _log(LOG_INFO, "> Verifying equivalence of encryption ctr modes for key size %.2f MiB\n",
             MiB(key_size));

        byte iv[KEYMIX_IV_SIZE] = {rand()};

        int err   = 0;
        byte *key = setup(key_size, true);
        byte *in  = setup(resource_size, true);

        byte *out1 = setup(resource_size, false);
        byte *out2 = setup(resource_size, false);

        int cmp = 0;
        byte *original = malloc(key_size);
        memcpy(original, key, key_size);

        ctx_t ctx;
        err = ctx_encrypt_init(&ctx, ENC_MODE_CTR, mix_type, one_way_type, key, key_size, iv, fanout);
        if (err) {
                _log(LOG_ERROR, "Encryption context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }
        encrypt(&ctx, in, out1, resource_size);
        ctx_free(&ctx);

        err = ctx_encrypt_init(&ctx, ENC_MODE_CTR_OPT, mix_type, one_way_type, key, key_size, iv, fanout);
        if (err) {
                _log(LOG_ERROR, "Encryption context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }
        encrypt(&ctx, in, out2, resource_size);
        ctx_free(&ctx);

        free(original);

        err += COMPARE(out1, out2, resource_size, "Encrypt (ctr) != Encrypt (ctr-opt)\n");

        free(key);
        free(out1);
        free(out2);
        return err;
}

int custom_checks(enc_mode_t enc_mode, mix_impl_t mix_type, mix_impl_t one_way_type) {
        mix_func_t mix;
        block_size_t block_size;

        if (get_mix_func(mix_type, &mix, &block_size)) {
                _log(LOG_ERROR, "Unknown mixing implementation\n");
                exit(EXIT_FAILURE);
        }

        byte *key = setup(block_size, false);

        byte iv[KEYMIX_IV_SIZE] = {0};
        uint8_t fanout          = 2;
        size_t size             = (rand() & 10) * block_size + (rand() % block_size);

        int err   = 0;
        byte *in  = setup(size, true);
        byte *enc = setup(size, false);
        byte *dec = setup(size, false);

        ctx_t ctx;
        err = ctx_encrypt_init(&ctx, enc_mode, mix_type, one_way_type, key, block_size, iv, fanout);
        if (err) {
                _log(LOG_ERROR, "Encryption context initialization exited with %d\n", err);
                exit(EXIT_FAILURE);
        }
        encrypt(&ctx, in, enc, size);
        encrypt(&ctx, enc, dec, size);

        err += COMPARE(in, dec, size, "Enc != INV(Dec)\n");

        free(key);
        free(in);
        free(enc);
        free(dec);
        return err;
}

#define CHECKED(F)                                                                                 \
        err = F;                                                                                   \
        if (err)                                                                                   \
                goto cleanup;

int main() {
        uint64_t rand_seed = time(NULL);
        srand(rand_seed);

        int err = 0;
        block_size_t block_size;
        mix_impl_t mix_type;
        mix_info_t mix_info;
        uint8_t fanouts[NUM_OF_FANOUTS];
        uint8_t fanouts_count;
        uint8_t fanout;

        _log(LOG_INFO, "[*] Verifying keymix with varying block sizes and fanouts\n\n");
        for (uint8_t i = 0; i < sizeof(BLOCK_SIZES) / sizeof(block_size_t); i++) {
                block_size = BLOCK_SIZES[i];
                fanouts_count = get_fanouts_from_block_size(block_size, NUM_OF_FANOUTS, fanouts);

                for (uint8_t j = 0; j < fanouts_count; j++) {
                        fanout = fanouts[j];

                        _log(LOG_INFO, "Verifying with block size %d and fanout %zu\n", block_size, fanout);
                        for (uint8_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                                CHECKED(verify_shuffles_with_varying_threads(block_size, fanout, l));
                                CHECKED(verify_keymix(block_size, fanout, l));
                        }
                        _log(LOG_INFO, "\n");
                }
        }

        _log(LOG_INFO, "[*] Verifying keymix and encryption with varying mixing implementations and fanouts\n\n");
        for (uint8_t i = 0; i < sizeof(MIX_TYPES) / sizeof(mix_impl_t); i++) {
                mix_type = MIX_TYPES[i];
                mix_info = *get_mix_info(mix_type);
                fanouts_count = get_fanouts_from_mix_type(mix_type, NUM_OF_FANOUTS, fanouts);

                CHECKED(custom_checks(ENC_MODE_CTR, mix_type, NONE));
                CHECKED(custom_checks(ENC_MODE_CTR_OPT, mix_type, NONE));
                if (mix_info.primitive != MIX_MATYAS_MEYER_OSEAS) {
                        CHECKED(custom_checks(ENC_MODE_OFB, mix_type, OPENSSL_MATYAS_MEYER_OSEAS_128));
                }

                for (uint8_t j = 0; j < fanouts_count; j++) {
                        uint8_t fanout = fanouts[j];

                        _log(LOG_INFO, "Verifying with mixing implementation %s and fanout %zu\n",
                             get_mix_name(mix_type), fanout);
                        for (uint8_t l = MIN_LEVEL; l <= MAX_LEVEL; l++) {
                                CHECKED(verify_multithreaded_keymix(mix_type, fanout, l));
                                CHECKED(verify_keymix_t(mix_type, fanout, l));
                                CHECKED(verify_enc(ENC_MODE_CTR, mix_type, NONE, fanout, l));
                                CHECKED(verify_enc(ENC_MODE_CTR_OPT, mix_type, NONE, fanout, l));
                                if (mix_info.primitive != MIX_MATYAS_MEYER_OSEAS) {
                                        CHECKED(verify_enc(ENC_MODE_OFB, mix_type,
                                                           OPENSSL_MATYAS_MEYER_OSEAS_128, fanout, l));
                                }
                                CHECKED(verify_enc_ctr_modes(mix_type, NONE, fanout, l)); // no change in the key, but crashes
                        }
                        _log(LOG_INFO, "\n");
                }
        }

cleanup:
        if (err)
                _log(LOG_INFO, "Failed, seed was %u\n", rand_seed);
        else
                _log(LOG_INFO, "All ok\n");
        return err;
}

#undef CHECKED
