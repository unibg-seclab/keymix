#include "refresh.h"

#include <string.h>

#include <openssl/evp.h>

#include "ctx.h"
#include "log.h"
#include "mix.h"
#include "utils.h"

// Maximum size of the OpenSSL encryption batch multiple of the AES block size
#define MAX_BATCH_SIZE 2147483520

void *w_thread_refresh(void *a) {
        thr_refresh_t *thr = (thr_refresh_t*) a;

        byte iv[BLOCK_SIZE_AES];
        size_t remaining_size;
        size_t curr_size;
        int outl;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
                _log(LOG_ERROR, "EVP_MD_CTX_create error\n");
        }

        // Set IV with 64 bits nonce and 64 bits counter
        // NOTE: This is aligned with the internal implementation of OpenSSL
        // at https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes.c
        
        // Initialize nonce
        memcpy(iv, thr->iv, 8);

        // Initialize counter
        byte *counter = iv + 8;
        for (int n = 7; n >= 0; n--) {
            counter[n] = thr->counter & 255;
            thr->counter >>= 8;
        }

        if (!EVP_EncryptInit(ctx, EVP_aes_128_ctr(), "super-secure-key", iv)) {
                _log(LOG_ERROR, "EVP_EncryptInit error\n");
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding

        // EVP_EncryptUpdate works up to sizes of 2^31 - 1. Bigger keys require
        // to call the function multiple times.
        remaining_size = thr->size;
        while (remaining_size) {
                curr_size = MIN(remaining_size, MAX_BATCH_SIZE);
                if (!EVP_EncryptUpdate(ctx, thr->out, &outl, thr->in, curr_size)) {
                        _log(LOG_ERROR, "EVP_EncryptUpdate error\n");
                }
                remaining_size -= curr_size;
        }

        // if (!EVP_EncryptFinal(ctx, out, &outl)) {
        //         _log(LOG_ERROR, "EVP_EncryptFinal_ex error\n");
        // }

        EVP_CIPHER_CTX_free(ctx);
        return NULL;
}

int multi_threaded_refresh(byte *in, byte *out, size_t size, byte *iv,
                           uint64_t counter, uint8_t nof_threads) {
        int err = 0;
        pthread_t threads[nof_threads];
        thr_refresh_t args[nof_threads];
        uint64_t tot_macros;
        uint64_t macros;
        size_t chunk_size;

        tot_macros = size / BLOCK_SIZE_AES;

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_refresh_t *arg = args + t;

                macros     = get_curr_thread_size(tot_macros, t, nof_threads);
                chunk_size = BLOCK_SIZE_AES * macros;

                arg->id      = t;
                arg->in      = in;
                arg->out     = out;
                arg->size    = chunk_size;
                arg->iv      = iv;
                arg->counter = counter;

                pthread_create(&threads[t], NULL, w_thread_refresh, arg);

                in += chunk_size;
                out += chunk_size;
                counter += macros;
        }

        _log(LOG_DEBUG, "[i] joining the threads...\n");
        for (uint8_t t = 0; t < nof_threads; t++) {
                err = pthread_join(threads[t], NULL);
                if (err) {
                        _log(LOG_ERROR, "pthread_join error %d (thread %d)\n", err, t);
                        return err;
                }
        }

        return err;
}
