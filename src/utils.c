#include "utils.h"

#include "config.h"
#include "log.h"
#include "types.h"
#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

void safe_explicit_bzero(void *ptr, size_t size) {
        if (ptr) {
                explicit_bzero(ptr, size);
        }
}

int barrier_init(barrier_status *state) {
        int err = pthread_mutex_init(&state->mutex, NULL);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_init error %d\n", err);
                return err;
        }
        err = pthread_cond_init(&state->cond, NULL);
        if (err) {
                _log(LOG_ERROR, "pthread_cond_init error %d\n", err);
                return err;
        }
        state->nof_waiting_thread = 0;
        state->round              = 0;
        return 0;
}

int barrier(barrier_status *state, int8_t nof_threads) {
        int err = pthread_mutex_lock(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_lock error %d", err);
                return err;
        }

        if (++state->nof_waiting_thread == nof_threads) {
                // Wake up every thread sleeping on cond
                state->round++;
                state->nof_waiting_thread = 0;
                err                       = pthread_cond_broadcast(&state->cond);
                if (err) {
                        _log(LOG_ERROR, "pthread_cond_broadcast error %d", err);
                        return err;
                }
        } else {
                // Sleep until the next round starts
                int8_t round = state->round;
                do {
                        err = pthread_cond_wait(&state->cond, &state->mutex);
                        if (err) {
                                _log(LOG_ERROR, "pthread_cond_wait error %d", err);
                                return err;
                        }
                } while (round == state->round);
        }

        err = pthread_mutex_unlock(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_unlock error %d", err);
                return err;
        }

        return 0;
}

int barrier_destroy(barrier_status *state) {
        int err = pthread_mutex_destroy(&state->mutex);
        if (err) {
                _log(LOG_ERROR, "pthread_mutex_destroy error %d\n", err);
                return err;
        }

        err = pthread_cond_destroy(&state->cond);
        if (err) {
                _log(LOG_ERROR, "pthread_cond_destroy error %d\n", err);
                return err;
        }

        return 0;
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

inline void reverse_16B(byte *data) {
        size_t size = SIZE_BLOCK;
        for (size_t i = 0; i < size / 2; i++) {
                byte temp          = data[i];
                data[i]            = data[size - 1 - i];
                data[size - 1 - i] = temp;
        }
}

inline void increment_counter(byte *macro, unsigned long step) {
        byte *second_block = macro + SIZE_BLOCK;
        // Note: we reverse because we are on little endian and we want
        // to increment what would be the MSB
        // Maybe there should be a check about this, although it's not that
        // important as of now, or we could just increment the LSB (left side),
        // since the effect is all the same on our schema
        reverse_16B(second_block);
        (*(uint128_t *)second_block) += step;
        reverse_16B(second_block);
}

inline uint64_t intpow(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        for (; exp > 0; exp--)
                res *= base;
        return res;
}

inline void memxor(void *dst, void *src, size_t size) {
        byte *d = (byte *)dst;
        byte *s = (byte *)src;

        for (; size > 0; size--) {
                *d++ ^= *s++;
        }
}
inline void memxor_ex(void *dst, void *a, void *b, size_t size) {
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
