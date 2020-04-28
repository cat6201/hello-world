#!/bin/sh
CFLAGS = -g
all:
	gcc $(CFLAGS) test.c -o test
