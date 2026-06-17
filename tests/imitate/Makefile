# SPDX-License-Identifier: GPL-2.0
VECTORS ?= ../../../amneziawg-go-proxy/device/testdata/imitate_vectors.txt
CFLAGS  := -O2 -Wall -Wextra -Werror -I. -I../../src

harness: harness.c ../../src/imitate.c ../../src/imitate.h imitate_shim.h
	$(CC) $(CFLAGS) -o harness harness.c ../../src/imitate.c

QINIT_SRC := ../../src/crypto/aes.c ../../src/crypto/sha256.c ../../src/qinit.c
qinit_kat: qinit_kat.c $(QINIT_SRC)
	$(CC) $(CFLAGS) -o qinit_kat qinit_kat.c $(QINIT_SRC)

test-qinit: qinit_kat
	./qinit_kat

.PHONY: test clean
test: harness
	./harness $(VECTORS)

clean:
	rm -f harness qinit_kat
