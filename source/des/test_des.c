/*
 * DES test file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdio.h>
#include <string.h>
#include "des.h"

int main(int argc, char* argv[])
{
	char *text = "TESTWY";
	unsigned char plaintext[8], cipher[8] = {0}, buffor[8] = {0};
	memcpy(plaintext, text, 8);

	des_ctx *ctx = des_make_ctx((unsigned char*)text);
	printf("plaintext: "); print_hex(plaintext, 8);
	des_crypt(ctx, plaintext, cipher, DES_ENCRYPT);
	printf("cipher: "); print_hex(cipher, 8);
	des_crypt(ctx, cipher, buffor, DES_DECRYPT);
	printf("decrypted: "); print_hex(buffor, 8);
	return 0;
}

