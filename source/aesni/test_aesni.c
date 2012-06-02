/*
 * AES-ni test file
 *
 * license: BSD
 * author: Michał Białas <michal.bialas@mbialas.pl>
 */

#include <stdio.h>

#include "aesni.h"
#include "../util/util.h"

int main(int argc, char* argv[])
{
	printf("AES enabled: %d\n", aesni_enabled());
}

