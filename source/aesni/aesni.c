/*
 * AES-NI crypt source file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 *
 * ref: http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set/
 */

#include "aesni.h"

/* see http://en.wikipedia.org/wiki/CPUID */
#define cpuid(func, ax, bx, cx, dx)\
	__asm__ ("cpuid": "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#define AESNI_CPUID_OP_FLAGS 0x1
#define AESNI_ENABLED_BIT 0x2000000
#define AESNI_ENABLED_SHIFT 25

inline __m128i aesni_128_assist(__m128i t1, __m128i t2);

int aesni_enabled()
{
	unsigned int a, b, c, d;
	cpuid(AESNI_CPUID_OP_FLAGS, a, b, c, d);
	return (c & AESNI_ENABLED_BIT) >> AESNI_ENABLED_SHIFT;
}

aesni_ctx* aesni_create_ctx(byte *key)
{
	aesni_ctx *ctx = (aesni_ctx*)malloc(sizeof(aesni_ctx));
	ctx->key = (byte*)malloc(16);
	memcpy(ctx->key, key, 16);

	__m128i t1, t2;
	t1 = _mm_loadu_si128((__m128i*)ctx->key);
	ctx->enc_keys[0] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x1);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[1] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x2);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[2] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x4);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[3] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x8);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[4] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x10);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[5] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x20);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[6] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x40);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[7] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x80);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[8] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x1b);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[9] = t1;

	t2 = _mm_aeskeygenassist_si128(t1, 0x36);
	t1 = aesni_128_assist(t1, t2);
	ctx->enc_keys[10] = t1;

	ctx->dec_keys[0] = ctx->enc_keys[10];
	for (int i = 1; i < 10; i++) {
		ctx->dec_keys[i] =  _mm_aesimc_si128(ctx->enc_keys[10 - i]);
	}
	ctx->dec_keys[10] = ctx->enc_keys[0];


	return ctx;
}

void aesni_encrypt(aesni_ctx *ctx, const byte *in, byte *out)
{
	register __m128i tmp;
	tmp = _mm_loadu_si128((__m128i*)in);
	tmp = _mm_xor_si128(tmp, ctx->enc_keys[0]);
	for (int i = 1; i < 10; i++) {
		tmp = _mm_aesenc_si128(tmp, ctx->enc_keys[i]);
	}
	tmp = _mm_aesenclast_si128(tmp, ctx->enc_keys[10]);
	_mm_storeu_si128((__m128i*)out, tmp);
}

void aesni_decrypt(aesni_ctx *ctx, const byte *in, byte *out)
{
	register __m128i tmp;
	tmp = _mm_loadu_si128((__m128i*)in);
	tmp = _mm_xor_si128(tmp, ctx->dec_keys[0]);
	for (int i = 1; i < 10; i++) {
		tmp = _mm_aesdec_si128(tmp, ctx->dec_keys[i]);
	}
	tmp = _mm_aesdeclast_si128(tmp, ctx->dec_keys[10]);
	_mm_storeu_si128(((__m128i*)out), tmp);
}

inline __m128i aesni_128_assist(__m128i t1, __m128i t2)
{
	__m128i t3;
	t2 = _mm_shuffle_epi32(t2 ,0xff);
	t3 = _mm_slli_si128(t1, 0x4);
	t1 = _mm_xor_si128(t1, t3);
	t3 = _mm_slli_si128(t3, 0x4);
	t1 = _mm_xor_si128(t1, t3);
	t3 = _mm_slli_si128(t3, 0x4);
	t1 = _mm_xor_si128(t1, t3);
	t1 = _mm_xor_si128(t1, t2);
	return t1;
}





