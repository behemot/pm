CC = gcc

all: test_aes

test_aes: test_aes.c aes.c aes.h
	$(CC) -std=c99 -Wall -Wextra -O2 -o test_aes test_aes.c aes.c ../util/util.c
