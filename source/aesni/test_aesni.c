/*
 * AES-ni test file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aesni.h"
#include "../util/util.h"

int main(int argc, char* argv[])
{
	int aesni_flag = aesni_enabled();
	printf("AES-NI enabled: %d\n", aesni_flag);
	if (!aesni_flag) {
		fprintf(stderr, "AES-NI not enabled!\n");
	}

	char* k = "TESTTESTTESTTEST";
	byte key[16], cipher[16], plain[16];
	memcpy(key, k, strlen(k));
	memcpy(plain, k, strlen(k));

	aesni_ctx *ctx = aesni_create_ctx(key);
	aesni_encrypt(ctx, plain, cipher);

	print_hex(cipher, 16);

	return 0;
}

