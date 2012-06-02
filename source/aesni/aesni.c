/*
 * AES-NI crypt source file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#define cpuid(func, ax, bx, cx, dx)\
	__asm__ __volatile__ ("cpuid":\
	"=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

#define AESNI_ENABLED_BIT 0x2000000


int aesni_enabled()
{
	unsigned int a, b, c, d;
	cpuid(1, a, b, c, d);
	return (c & AESNI_ENABLED_BIT);
}

