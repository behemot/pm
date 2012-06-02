/*
 * DES crypt header file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdint.h>

#ifndef DES_H
#define DES_H

#define DES_ENCRYPT 0 /* Encrypting mode */
#define DES_DECRYPT 1 /* Decrypting mode */

#define DES_SUB_KEYS_N 16

#define DEBUG 0

typedef struct _des_ctx {
	unsigned char *key;
	uint64_t sub_keys[DES_SUB_KEYS_N];
} des_ctx;

des_ctx* des_make_ctx(unsigned char *key);

void des_crypt(des_ctx *ctx, const unsigned char *plaintext, unsigned char *cipher, int mode);

#endif /* DES_H */

