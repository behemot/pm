/*
 * AES-ni crypt header file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <wmmintrin.h>
#include <stdint.h>

#include "../crypt.h"

#ifndef AESNI_H
#define AESNI_H

#define AESNI_ENCRYPT 0 /* Encrypting mode */
#define AESNI_DECRYPT 1 /* Decrypting mode */

#define AESNI_128_SUB_KEYS_N 10
#define AESNI_192_SUB_KEYS_N 12
#define AESNI_256_SUB_KEYS_N 14
#define AESNI_SUB_KEYS_MAX_N AESNI_256_SUB_KEYS_N

#define DEBUG 0

typedef struct _aesni_ctx {
	byte *key;
	uint64_t sub_keys[AESNI_SUB_KEYS_MAX_N];
} aesni_ctx;

int aesni_enabled();

aesni_ctx* aesni_create_ctx(byte *key);

void aesni_encrypt(aesni_ctx *ctx, byte *plaintext, byte *cipher);

#endif /* AESNI_H */

