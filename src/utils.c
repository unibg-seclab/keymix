#include "utils.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "types.h"

typedef struct {
        byte *dst;
        byte *a;
        byte *b;
        size_t size;
} thr_memxor_t;

void safe_explicit_bzero(void *ptr, size_t size) {
        if (ptr) {
                explicit_bzero(ptr, size);
        }
}

byte *checked_malloc(size_t size) {
        byte *buf = (byte *)malloc(size);
        if (buf == NULL) {
                printf("(!) Error occured while allocating memory\n");
                // No need to free, as free is a no-op when the ptr is NULL
                exit(1);
        }
        return buf;
}

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline void memxor(void *dst, void *a, void *b, size_t size) {
        byte *d  = (byte *)dst;
        byte *s1 = (byte *)a;
        byte *s2 = (byte *)b;

        for (; size > 0; size--) {
                *d++ = *s1++ ^ *s2++;
        }
}

inline void memswap(byte *restrict a, byte *restrict b, size_t bytes) {
        byte *a_end = a + bytes;
        while (a < a_end) {
                byte tmp = *a;
                *a++     = *b;
                *b++     = tmp;
        }
}

// Get the current thread window start in #macros
uint64_t get_curr_thread_offset(uint64_t tot_macros, uint8_t thread_id,
                                uint8_t nof_threads) {
        uint64_t extra_macros;
        uint64_t offset;

        extra_macros = MIN(tot_macros % nof_threads, thread_id);
        offset       = tot_macros / nof_threads * thread_id + extra_macros;

        return offset;
}

uint64_t get_curr_thread_size(uint64_t tot_macros, uint8_t thread_id,
                              uint8_t nof_threads) {
        bool extra_macro;
        uint64_t macros;

        extra_macro = (thread_id < tot_macros % nof_threads);
        macros      = tot_macros / nof_threads + extra_macro;

        return macros;
}

void *w_thread_memxor(void *a) {
        thr_memxor_t *thr = (thr_memxor_t*) a;
        memxor(thr->dst, thr->a, thr->b, thr->size);
        return NULL;
}

int multi_threaded_memxor(byte *dst, byte *a, byte *b, size_t size,
                          uint8_t nof_threads) {
        int err = 0;
        pthread_t threads[nof_threads];
        thr_memxor_t args[nof_threads];
        size_t chunk_size;

        for (uint8_t t = 0; t < nof_threads; t++) {
                thr_memxor_t *arg = args + t;

                chunk_size = get_curr_thread_size(size, t, nof_threads);

                arg->dst  = dst;
                arg->a    = a;
                arg->b    = b;
                arg->size = chunk_size;

                pthread_create(&threads[t], NULL, w_thread_memxor, arg);

                dst += chunk_size;
                a += chunk_size;
                b += chunk_size;
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
