/*
 * AES crypt source file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include "aes.h"

void sub_bytes();
void shift_rows();
void mix_columns();
void add_round_key();
void inv_shift_rows();
void inv_sub_bytes();
void inv_mix_columns();

aes_ctx* aes_create_ctx(byte *key)
{
	aes_ctx *ctx = (aes_ctx*)malloc(sizeof(aes_ctx));
	ctx->key = (byte*)malloc(16);
	memcpy(ctx->key, key, 16);
	return ctx;
}

void aes_encrypt(aes_ctx *ctx, const byte *in, byte *out)
{
	add_round_key();
	for (int i = 0; i < 10; i++) {
		sub_bytes();
		shift_rows();
		mix_columns();
		add_round_key();
	}
	sub_bytes();
	shift_rows();
	add_round_key();
}

void aes_decrypt(aes_ctx *ctx, const byte *in, byte *out)
{
	add_round_key();
	for (int i = 0; i < 10; i++) {
		inv_shift_rows();
		inv_sub_bytes();
		add_round_key();
		inv_mix_columns();
	}
	inv_shift_rows();
	inv_sub_bytes();
	add_round_key();
}

void sub_bytes()
{

}

void shift_rows()
{

}

void mix_columns()
{

}

void add_round_key()
{

}

void inv_shift_rows()
{

}

void inv_sub_bytes()
{

}

void inv_mix_columns()
{

}



