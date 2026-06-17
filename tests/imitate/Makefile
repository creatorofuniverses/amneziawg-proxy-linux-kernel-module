# SPDX-License-Identifier: GPL-2.0
VECTORS ?= ../../../amneziawg-go-proxy/device/testdata/imitate_vectors.txt
CFLAGS  := -O2 -Wall -Wextra -Werror -I. -I../../src

harness: harness.c ../../src/imitate.c ../../src/imitate.h imitate_shim.h
	$(CC) $(CFLAGS) -o harness harness.c ../../src/imitate.c

# Task 2: aes.c + sha256.c; qinit.c will be added in Task 3.
QINIT_SRC := ../../src/crypto/aes.c ../../src/crypto/sha256.c
qinit_kat: qinit_kat.c $(QINIT_SRC)
	$(CC) $(CFLAGS) -o qinit_kat qinit_kat.c $(QINIT_SRC)

test-qinit: qinit_kat
	./qinit_kat

.PHONY: test clean
test: harness
	./harness $(VECTORS)

clean:
	rm -f harness qinit_kat
