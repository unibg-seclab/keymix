#ifndef AESNI_H
#define AESNI_H

#include "types.h"

#include <wmmintrin.h>

#define AESNI_256_KEY_SCHEDULE_SIZE 15
#define AESNI_128_KEY_SCHEDULE_SIZE 11

void aes256_key_expansion(byte *key, __m128i *key_schedule);
void aes256_enc(__m128i *key_schedule, byte *data, byte *out);

void aes128_key_expansion(byte *key, __m128i *key_schedule);
void aes128_enc(__m128i *key_schedule, byte *data, byte *out);

#endif
