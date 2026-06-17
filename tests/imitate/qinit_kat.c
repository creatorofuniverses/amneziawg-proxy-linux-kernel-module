// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "imitate_shim.h"
#include "../../src/crypto/aes.h"

static int fails;

static int eq(const char *name, const u8 *got, const u8 *want, int n)
{
	if (memcmp(got, want, n) == 0) { printf("PASS %s\n", name); return 1; }
	printf("FAIL %s\n", name);
	fails++;
	return 0;
}

/* FIPS-197 Appendix B / C.1: AES-128 single block. */
static void test_aes128_fips197(void)
{
	const u8 key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	const u8 pt[16]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	const u8 ct[16]  = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
			    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	struct aes128_ctx c;
	u8 out[16];

	aes128_set_encrypt_key(&c, key);
	aes128_encrypt_block(&c, pt, out);
	eq("aes128_fips197", out, ct, 16);
}

int main(void)
{
	test_aes128_fips197();
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
	return fails ? 1 : 0;
}
