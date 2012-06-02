/*
 * DES crypt source file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "des.h"

int const key_length = 8;
int const rounds_n = 16;
int const block_size = 8;

const unsigned char IP[64] = {
	6, 14, 22, 30, 38, 46, 54, 62,
	4, 12, 20, 28, 36, 44, 52, 60,
	2, 10, 18, 26, 34, 42, 50, 58,
	0, 8, 16, 24, 32, 40, 48, 56,
	7, 15, 23, 31, 39, 47, 55, 63,
	5, 13, 21, 29, 37, 45, 53, 61,
	3, 11, 19, 27, 35, 43, 51, 59,
	1, 9, 17, 25, 33, 41, 49, 57,
};

const unsigned char IP1[64] = {
	24, 56, 16, 48, 8, 40, 0, 32,
	25, 57, 17, 49, 9, 41, 1, 33,
	26, 58, 18, 50, 10, 42, 2, 34,
	27, 59, 19, 51, 11, 43, 3, 35,
	28, 60, 20, 52, 12, 44, 4, 36,
	29, 61, 21, 53, 13, 45, 5, 37,
	30, 62, 22, 54, 14, 46, 6, 38,
	31, 63, 23, 55, 15, 47, 7, 39,
};

const unsigned char P[32] = {
	16, 25, 12, 11, 3, 20, 4, 15,
	31, 17, 9, 6, 27, 14, 1, 22,
	30, 24, 8, 18, 0, 5, 29, 23,
	13, 19, 2, 26, 10, 21, 28, 7
};

const unsigned char E[48] = {
	0, 31, 30, 29, 28, 27, 28, 27,
	26, 25, 24, 23, 24, 23, 22, 21,
	20, 19, 20, 19, 18, 17, 16, 15,
	16, 15, 14, 13, 12, 11, 12, 11,
	10, 9, 8, 7, 8, 7, 6, 5,
	4, 3, 4, 3, 2, 1, 0, 31
};

const unsigned char PC1[56] = {
	7, 15, 23, 31, 39, 47, 55, 63,
	6, 14, 22, 30, 38, 46, 54, 62,
	5, 13, 21, 29, 37, 45, 53, 61,
	4, 12, 20, 28, 1, 9, 17, 25,
	33, 41, 49, 57, 2, 10, 18, 26,
	34, 42, 50, 58, 3, 11, 19, 27,
	35, 43, 51, 59, 36, 44, 52, 60,
};

const unsigned char PC2[48] = {
	42, 39, 45, 32, 55, 51, 53, 28,
	41, 50, 35, 46, 33, 37, 44, 52,
	30, 48, 40, 49, 29, 36, 43, 54,
	15, 4, 25, 19, 9, 1, 26, 16,
 	5, 11, 23, 8, 12, 7, 17, 0,
	22, 3, 10, 14, 6, 20, 27, 24,
};

const unsigned char sbox[8][4][16] = {
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
	},

	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
	},

	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
	},

	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
	},

	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
	},

	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
	},

	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
	},

	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
	}
};

des_ctx* des_make_ctx(unsigned char *key)
{
	des_ctx *ctx = (des_ctx*)malloc(sizeof(des_ctx));
	ctx->key = (unsigned char*)malloc(sizeof(unsigned char) * (key_length + 1));
	//TODO: compute sub-keys
	for (int i = 0; i < DES_SUB_KEYS_N; i++) {
		ctx->sub_keys[i] = (i * 64733) << i;
		//ctx->sub_keys[i] = 0;
	}
	memcpy(ctx->key, key, (key_length + 1));
	return ctx;
}

inline void byte2rlints(unsigned char *src, uint32_t *left, uint32_t *right)
{
	*left = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3];
	*right = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7];
}

inline void rlints2byte(unsigned char *dst, uint32_t *left, uint32_t *right)
{
	dst[0] = (*left & 0xFF000000) >> 24;
	dst[1] = (*left & 0x00FF0000) >> 16;
	dst[2] = (*left & 0x0000FF00) >> 8;
	dst[3] = (*left & 0x000000FF);
	dst[4] = (*right & 0xFF000000) >> 24;
	dst[5] = (*right & 0x00FF0000) >> 16;
	dst[6] = (*right & 0x0000FF00) >> 8;
	dst[7] = (*right & 0x000000FF);
}

inline void cpy_block2buffor(const unsigned char *src, unsigned char *buf)
{
	for (int i = 0; i < block_size; i++) {
		buf[i] = src[i];
	}
}

void init_perm(unsigned char *src)
{
	unsigned char buffor[block_size];
	for (size_t i = 0; i < sizeof(buffor); i++) {
		buffor[i] = 0;
	} 
	for (size_t i = 0; i < sizeof(IP); i++) {
		buffor[(sizeof(IP) - 1 - i) / block_size] |= ((src[IP[i] / block_size] >> (IP[i] % block_size)) & 0x1) << ((sizeof(IP) - 1 - i) % block_size);
	}
	cpy_block2buffor(buffor, src);
}

void final_perm(unsigned char *src)
{
	unsigned char buffor[block_size];
	for (size_t i = 0; i < sizeof(buffor); i++) {
		buffor[i] = 0;
	}
	for (size_t i = 0; i < sizeof(IP1); i++) {
		buffor[(sizeof(IP1) - 1 - i) / block_size] |= ((src[IP1[i] / block_size] >> (IP1[i] % block_size)) & 0x1) << ((sizeof(IP1) - 1 - i) % block_size);
	}
	cpy_block2buffor(buffor, src);
}

inline uint32_t round_perm(uint32_t block)
{
	uint32_t work = 0;
	for (size_t i = 0; i < sizeof(P); i++) {
		work |= ((block >> P[i]) & 0x1) << (sizeof(P) - 1 - i);
	}
	return work;
}

inline uint64_t block_expansion(uint32_t block)
{
	uint64_t work = 0;
	for (int i = 0; i < (int)sizeof(E); i++) {
		work |= ((block >> E[i]) & 0x1) << (sizeof(E) - 1 - i);
	}
	return work;
}

inline uint32_t substitution(uint64_t block)
{
	uint64_t work = 0;
	unsigned char sel, row, col;
	for (int i = 0; i < block_size; i++) {
		sel = (block & 0x3f);
		row = ((sel >> 5) & 0x1) << 1;
		row |= sel & 0x1;
		col = (sel >> 1) & 0xf;
		work |= sbox[block_size - 1 - i][row][col];
		block >>= 6;
	}
	return (uint32_t)work;
}

uint32_t round_fun(des_ctx *ctx, int key_n, uint32_t block)
{
	uint64_t work;
	work = block_expansion(block) ^ ctx->sub_keys[key_n];
	printf("%lX\n", work);
	printf("%lX\n", block_expansion(block));
	block = substitution(work);
	block = round_perm(block);
	return block;
}

void des_crypt(des_ctx *ctx, const unsigned char *plaintext, unsigned char *cipher, int mode)
{
	uint32_t left, right, tmp;
	unsigned char buffor[block_size];

	cpy_block2buffor(plaintext, buffor);
	init_perm(buffor);
	byte2rlints(buffor, &left, &right);
	for (int i = 0; i < rounds_n; i++) {
		tmp = right;
		right = left ^ round_fun(ctx, (mode == DES_ENCRYPT ? i : rounds_n - 1 - i), right);
		left = tmp;
	}
	rlints2byte(cipher, &right, &left);
	final_perm(cipher);
}

