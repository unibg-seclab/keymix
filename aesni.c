#include "aesni.h"

#include <wmmintrin.h>
#include <wolfssl/wolfcrypt/aes.h>

// Implemented following the Intel white paper here
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

// -------------------------------------------------------- AES 128

__m128i aes_128_assist(__m128i key, __m128i keygened) {
        keygened = _mm_shuffle_epi32(keygened, 0xff);
        key      = _mm_xor_si128(key, _mm_slli_si128(key, 0x4));
        key      = _mm_xor_si128(key, _mm_slli_si128(key, 0x4));
        key      = _mm_xor_si128(key, _mm_slli_si128(key, 0x4));
        return _mm_xor_si128(key, keygened);
}

void aes_128_key_expansion(byte *enc_key, __m128i *key_schedule) {
#define KEY_EXP(k, rcon) aes_128_assist(k, _mm_aeskeygenassist_si128(k, rcon))
#define KEYROUND(i, rcon) key_schedule[i] = KEY_EXP(key_schedule[i - 1], rcon)

        key_schedule[0] = _mm_loadu_si128((const __m128i *)enc_key);
        KEYROUND(1, 0x01);
        KEYROUND(2, 0x02);
        KEYROUND(3, 0x04);
        KEYROUND(4, 0x08);
        KEYROUND(5, 0x10);
        KEYROUND(6, 0x20);
        KEYROUND(7, 0x40);
        KEYROUND(8, 0x80);
        KEYROUND(9, 0x1B);
        KEYROUND(10, 0x36);

#undef KEY_EXP
#undef KEYROUND
}

void aes128_enc(__m128i *key_schedule, byte *plainText, byte *cipherText) {
        __m128i m = _mm_loadu_si128((__m128i *)plainText);

        m = _mm_xor_si128(m, key_schedule[0]);
        m = _mm_aesenc_si128(m, key_schedule[1]);
        m = _mm_aesenc_si128(m, key_schedule[2]);
        m = _mm_aesenc_si128(m, key_schedule[3]);
        m = _mm_aesenc_si128(m, key_schedule[4]);
        m = _mm_aesenc_si128(m, key_schedule[5]);
        m = _mm_aesenc_si128(m, key_schedule[6]);
        m = _mm_aesenc_si128(m, key_schedule[7]);
        m = _mm_aesenc_si128(m, key_schedule[8]);
        m = _mm_aesenc_si128(m, key_schedule[9]);
        m = _mm_aesenclast_si128(m, key_schedule[10]);

        _mm_storeu_si128((__m128i *)cipherText, m);
}

void aes128enc(byte *data, byte *out, byte *key, size_t blocks) {
        __m128i key_schedule[11];
        aes_128_key_expansion(key, key_schedule);
        byte *last = data + blocks * AES_BLOCK_SIZE;
        for (; data < last; data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE) {
                aes128_enc(key_schedule, data, out);
        }
}

// -------------------------------------------------------- AES 256

__m128i key_256_assist_1(__m128i key1, __m128i m) {
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

__m128i key_256_assist_2(__m128i key1, __m128i key2) {
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

void aes_256_key_expansion(byte *key, __m128i *key_schedule) {
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
        int j;

        m = _mm_loadu_si128((__m128i *)data);
        m = _mm_xor_si128(m, key_schedule[0]);

        for (j = 1; j < 14; j++) {
                m = _mm_aesenc_si128(m, key_schedule[j]);
        }
        m = _mm_aesenclast_si128(m, key_schedule[j]);
        _mm_storeu_si128((__m128i *)out, m);
}

void aes256enc(byte *data, byte *out, byte *key, size_t blocks) {
        __m128i key_schedule[15];
        aes_256_key_expansion(key, key_schedule);
        byte *last = data + blocks * AES_BLOCK_SIZE;
        for (; data < last; data += AES_BLOCK_SIZE, out += AES_BLOCK_SIZE) {
                aes256_enc(key_schedule, data, out);
        }
}
