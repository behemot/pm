/*
 * AES crypt header file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include "../crypt.h"
#include "../util/util.h"

#ifndef AES_H
#define AES_H

#define DEBUG 0

typedef struct _aes_ctx {
	byte *key;
} aes_ctx;

aes_ctx* aes_create_ctx(byte *key);

void aes_encrypt(aes_ctx *ctx, const byte *in, byte *out);

void aes_decrypt(aes_ctx *ctx, const byte *in, byte *out);

#endif /* AES_H */

