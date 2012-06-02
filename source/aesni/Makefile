CC = gcc

all: test_aesni

test_aesni: test_aesni.c aesni.c aesni.h
	$(CC) -std=c99 -Wall -Wextra -O2 -o test_aesni test_aesni.c aesni.c
