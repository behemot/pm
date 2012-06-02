/*
 * util source header file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include<stdio.h>

void print_hex(unsigned char *str, int n)
{
	printf("0x");
	for (int i = 0; i < n; i++) {
		printf("%02hhX", str[i]);
	}
	printf("\n");
}

char* char2bit(unsigned char arg)
{
	#define char_bit_n (sizeof(char) * 8)
	static char buf[char_bit_n + 1];
	buf[char_bit_n - 1] = '\0';
	for (int i = 0; i < (int)char_bit_n; i++) {
		buf[i] = ((arg >> (char_bit_n - 1 - i)) & 0x1) + '0';
	}
	return buf;
	#undef char_bit_n
}




