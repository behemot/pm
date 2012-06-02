/*
 * AES-NI crypt source file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include "aesni.h"

/* see http://en.wikipedia.org/wiki/CPUID */
#define cpuid(func, ax, bx, cx, dx)\
	__asm__ ("cpuid": "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#define AESNI_CPUID_OP_FLAGS 0x1
#define AESNI_ENABLED_BIT 0x2000000
#define AESNI_ENABLED_SHIFT 25


int aesni_enabled()
{
	unsigned int a, b, c, d;
	cpuid(AESNI_CPUID_OP_FLAGS, a, b, c, d);
	return (c & AESNI_ENABLED_BIT) >> AESNI_ENABLED_SHIFT;
}

aesni_ctx* aesni_create_ctx(byte *key)
{
	aesni_ctx *ctx = (aesni_ctx*)malloc(sizeof(aesni_ctx));
	//ctx->key = (unsigned char*)malloc(sizeof(byte) * (key_length + 1));
	return ctx;
}

void aesni_encrypt(aesni_ctx *ctx, byte *plaintext, byte *cipher)
{
	__m128i key;
	register __m128i tmp;
	tmp = _mm_loadu_si128(&((__m128i*)plaintext)[0]);
	tmp = _mm_xor_si128(tmp, key);
	for (int i = 1; i < 10; i++) {
		tmp = _mm_aesenc_si128(tmp, key);
	}
	tmp = _mm_aesenclast_si128(tmp, key);
	_mm_storeu_si128((__m128i*)cipher, tmp);
}


/*}
void AES_ECB_decrypt(const unsigned char *in,
unsigned char *out,
unsigned long length,
const char *key,
int number_of_rounds)
{
__m128i tmp;
int i,j;
//pointer to the CIPHERTEXT
//pointer to the DECRYPTED TEXT buffer
//text length in bytes
//pointer to the expanded key schedule
//number of AES rounds 10,12 or 14
if(length%16)
length = length/16+1;
else
length = length/16;
for(i=0; i < length; i++){
tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
for(j=1; j <number_of_rounds; j++){
tmp = _mm_aesdec_si128 (tmp,((__m128i*)key)[j]);
}
tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)key)[j]);
_mm_storeu_si128 (&((__m128i*)out)[i],tmp);
}
}*/




