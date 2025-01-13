#include "aesni.h"

#include "types.h"

#include <stdint.h>
#include <wmmintrin.h>

// Implemented following the Intel white paper here
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

// --------------------------------------- AES 256

inline __m128i key_256_assist_1(__m128i key1, __m128i m) {
        __m128i tmp;
        m = _mm_shuffle_epi32(m, 0xff);

        tmp  = _mm_slli_si128(key1, 0x4);
        key1 = _mm_xor_si128(key1, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        key1 = _mm_xor_si128(key1, tmp);

        tmp  = _mm_slli_si128(tmp, 0x4);
        key1 = _mm_xor_si128(key1, tmp);
        key1 = _mm_xor_si128(key1, m);
        return key1;
}

inline __m128i key_256_assist_2(__m128i key1, __m128i key2) {
        __m128i tmp = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(key1, 0x0), 0xaa);
        __m128i m   = _mm_slli_si128(key2, 0x4);

        key2 = _mm_xor_si128(key2, m);

        m    = _mm_slli_si128(m, 0x4);
        key2 = _mm_xor_si128(key2, m);

        m    = _mm_slli_si128(m, 0x4);
        key2 = _mm_xor_si128(key2, m);
        key2 = _mm_xor_si128(key2, tmp);

        return key2;
}

void aes256_key_expansion(byte *key, __m128i *key_schedule) {
#define KEYROUND_1(i, rcon)                                                                        \
        key_schedule[i] = key_256_assist_1(key_schedule[i - 2],                                    \
                                           _mm_aeskeygenassist_si128(key_schedule[i - 1], rcon))
#define KEYROUND_2(i) key_schedule[i] = key_256_assist_2(key_schedule[i - 1], key_schedule[i - 2])

        key_schedule[0] = _mm_loadu_si128((__m128i *)key);
        key_schedule[1] = _mm_loadu_si128((__m128i *)(key + 16));

        KEYROUND_1(2, 0x01);
        KEYROUND_2(3);
        KEYROUND_1(4, 0x02);
        KEYROUND_2(5);
        KEYROUND_1(6, 0x04);
        KEYROUND_2(7);
        KEYROUND_1(8, 0x08);
        KEYROUND_2(9);
        KEYROUND_1(10, 0x10);
        KEYROUND_2(11);
        KEYROUND_1(12, 0x20);
        KEYROUND_2(13);
        KEYROUND_1(14, 0x40);

#undef KEYROUND_1
#undef KEYROUND_2
}

void aes256_enc(__m128i *key_schedule, byte *data, byte *out) {
        __m128i m;
        uint8_t j;

        m = _mm_loadu_si128((__m128i *)data);
        m = _mm_xor_si128(m, key_schedule[0]);

        for (j = 1; j < AESNI_256_KEY_SCHEDULE_SIZE - 1; j++) {
                m = _mm_aesenc_si128(m, key_schedule[j]);
        }
        m = _mm_aesenclast_si128(m, key_schedule[j]);
        _mm_storeu_si128((__m128i *)out, m);
}

// --------------------------------------- AES 256

inline __m128i key_128_assist(__m128i key, __m128i m) {
        __m128i tmp;
        m   = _mm_shuffle_epi32(m, 0xff);
        tmp = _mm_slli_si128(key, 0x4);
        key = _mm_xor_si128(key, tmp);
        tmp = _mm_slli_si128(tmp, 0x4);
        key = _mm_xor_si128(key, tmp);
        tmp = _mm_slli_si128(tmp, 0x4);
        key = _mm_xor_si128(key, tmp);
        key = _mm_xor_si128(key, m);
        return key;
}

void aes128_key_expansion(byte *key, __m128i *key_schedule) {
#define KEYROUND(i, rcon)                                                                          \
        key_schedule[i] = key_128_assist(key_schedule[i - 1],                                      \
                                         _mm_aeskeygenassist_si128(key_schedule[i - 1], rcon));

        key_schedule[0] = _mm_loadu_si128((__m128i *)key);
        KEYROUND(1, 0x1);
        KEYROUND(2, 0x2);
        KEYROUND(3, 0x4);
        KEYROUND(4, 0x8);
        KEYROUND(5, 0x10);
        KEYROUND(6, 0x20);
        KEYROUND(7, 0x40);
        KEYROUND(8, 0x80);
        KEYROUND(9, 0x1b);
        KEYROUND(10, 0x36);

#undef KEYROUND
}

void aes128_enc(__m128i *key_schedule, byte *data, byte *out) {
        __m128i m;
        uint8_t j;

        m = _mm_loadu_si128((__m128i *)data);
        m = _mm_xor_si128(m, key_schedule[0]);

        for (j = 1; j < AESNI_128_KEY_SCHEDULE_SIZE - 1; j++) {
                m = _mm_aesenc_si128(m, key_schedule[j]);
        }
        m = _mm_aesenclast_si128(m, key_schedule[j]);
        _mm_storeu_si128((__m128i *)out, m);
}
