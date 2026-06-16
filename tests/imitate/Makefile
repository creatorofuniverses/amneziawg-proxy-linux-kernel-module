# SPDX-License-Identifier: GPL-2.0
VECTORS ?= ../../../amneziawg-go-proxy/device/testdata/imitate_vectors.txt
CFLAGS  := -O2 -Wall -Wextra -Werror -I. -I../../src

harness: harness.c ../../src/imitate.c ../../src/imitate.h imitate_shim.h
	$(CC) $(CFLAGS) -o harness harness.c ../../src/imitate.c

.PHONY: test clean
test: harness
	./harness $(VECTORS)

clean:
	rm -f harness
