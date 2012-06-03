/*
 * AES-ni crypt header file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <wmmintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../crypt.h"
#include "../util/util.h"

#ifndef AESNI_H
#define AESNI_H

#define AESNI_ENCRYPT 0 /* Encrypting mode */
#define AESNI_DECRYPT 1 /* Decrypting mode */

#define AESNI_128_SUB_KEYS_N 11
#define AESNI_192_SUB_KEYS_N 13
#define AESNI_256_SUB_KEYS_N 15
#define AESNI_SUB_KEYS_MAX_N AESNI_256_SUB_KEYS_N

#define DEBUG 0

typedef struct _aesni_ctx {
	byte *key;
	__m128i enc_keys[AESNI_SUB_KEYS_MAX_N]; //@todo alloc dynamically
	__m128i dec_keys[AESNI_SUB_KEYS_MAX_N]; //@todo alloc dynamically
} aesni_ctx;

int aesni_enabled();

aesni_ctx* aesni_create_ctx(byte *key);

void aesni_encrypt(aesni_ctx *ctx, const byte *in, byte *out);

void aesni_decrypt(aesni_ctx *ctx, const byte *in, byte *out);

#endif /* AESNI_H */

