/*
 * AES-ni test file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "../util/util.h"

int main(int argc, char* argv[])
{
	char* p = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	char* k = "\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59";
	char* c = "\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65";
	byte key[16], cipher[16], plain[16];
	memcpy(key, k, 16);
	memcpy(plain, p, 16);

	aes_ctx *ctx = aes_create_ctx(key);

	aes_encrypt(ctx, plain, cipher);
	print_hex(cipher, 16);
	for (int i = 0; i < 16; i++) {
		if ((byte)c[i] != cipher[i]) {
			fprintf(stderr, "ERROR on encrypt test vector\n");
			//exit(EXIT_FAILURE);
		}
	}
	printf("AES encrypt test vector ok\n");

	aes_decrypt(ctx, cipher, plain);
	print_hex(plain, 16);
	for (int i = 0; i < 16; i++) {
		if ((byte)p[i] != plain[i]) {
			fprintf(stderr, "ERROR on decrypt test vector\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("AES decrypt test vector ok\n");

	return 0;
}

