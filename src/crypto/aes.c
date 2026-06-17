// SPDX-License-Identifier: GPL-2.0
/*
 * AES-128 block encrypt — FIPS-197, encrypt-only.
 * No constant-time requirement: qinit keys are public-derivable (RFC 9001 §5.2).
 */
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aes.h"

/* FIPS-197 Figure 7: forward S-box */
static const u8 sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* FIPS-197 §5.2: round constants (Rcon[1..10]) */
static const u8 rcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* Load a big-endian 32-bit word from 4 bytes */
static u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

/* SubWord: apply S-box to each byte of a 32-bit word */
static u32 sub_word(u32 w)
{
	return ((u32)sbox[(w >> 24) & 0xff] << 24) |
	       ((u32)sbox[(w >> 16) & 0xff] << 16) |
	       ((u32)sbox[(w >>  8) & 0xff] <<  8) |
	       ((u32)sbox[(w)       & 0xff]);
}

/* RotWord: left-rotate word by 8 bits */
static u32 rot_word(u32 w)
{
	return (w << 8) | (w >> 24);
}

/*
 * aes128_set_encrypt_key — FIPS-197 §5.2 KeyExpansion.
 * Expands 16-byte key into 44 round-key words stored in ctx->rk[0..43].
 */
void aes128_set_encrypt_key(struct aes128_ctx *ctx, const u8 key[16])
{
	int i;
	u32 *rk = ctx->rk;

	/* First 4 words are the key itself */
	for (i = 0; i < 4; i++)
		rk[i] = load_be32(key + 4 * i);

	/* Expand words 4..43 */
	for (i = 4; i < 44; i++) {
		u32 temp = rk[i - 1];

		if (i % 4 == 0)
			temp = sub_word(rot_word(temp)) ^ ((u32)rcon[i / 4 - 1] << 24);
		rk[i] = rk[i - 4] ^ temp;
	}
}

/* xtime: multiply by 2 in GF(2^8) with the AES irreducible polynomial */
static u8 xtime(u8 b)
{
	return (b << 1) ^ ((b >> 7) ? 0x1b : 0x00);
}

/*
 * shift_rows — FIPS-197 §5.1.2 ShiftRows.
 *
 * State layout: flat u8 s[16], column-major (FIPS-197 §3.4).
 * s[4*col + row]: col in [0..3], row in [0..3].
 * Row r occupies s[r], s[4+r], s[8+r], s[12+r].
 *
 * Row 1 shifts left by 1, row 2 by 2, row 3 by 3.
 */
static void shift_rows(u8 *s)
{
	u8 tmp;

	/* row 1: left-rotate by 1 */
	tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;

	/* row 2: left-rotate by 2 (swap pairs) */
	tmp = s[2];  s[2]  = s[10]; s[10] = tmp;
	tmp = s[6];  s[6]  = s[14]; s[14] = tmp;

	/* row 3: left-rotate by 3 (= right-rotate by 1) */
	tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
}

/*
 * add_round_key — FIPS-197 §5.1.4 AddRoundKey.
 * XOR columns of state with round-key words rk[base..base+3].
 * Each word is big-endian: byte 0 (MSB) is row 0.
 */
static void add_round_key(u8 *s, const u32 *rk, int base)
{
	int col;

	for (col = 0; col < 4; col++) {
		u32 w = rk[base + col];

		s[4 * col + 0] ^= (u8)(w >> 24);
		s[4 * col + 1] ^= (u8)(w >> 16);
		s[4 * col + 2] ^= (u8)(w >>  8);
		s[4 * col + 3] ^= (u8)(w);
	}
}

/*
 * aes128_encrypt_block — FIPS-197 §5.1 Cipher.
 * in/out are 16-byte arrays in column-major order (AES §3.4):
 *   byte index i → state[i mod 4][i / 4] (row, col).
 */
void aes128_encrypt_block(const struct aes128_ctx *ctx, const u8 in[16],
			  u8 out[16])
{
	u8 s[16];
	const u32 *rk = ctx->rk;
	int round, col;
	u8 a, b, c, d;

	memcpy(s, in, 16);

	add_round_key(s, rk, 0);

	for (round = 1; round <= 9; round++) {
		/* SubBytes */
		for (col = 0; col < 16; col++)
			s[col] = sbox[s[col]];

		shift_rows(s);

		/*
		 * MixColumns — FIPS-197 §5.1.3.
		 * Each column [a b c d]^T is multiplied by:
		 * [2 3 1 1]
		 * [1 2 3 1]
		 * [1 1 2 3]
		 * [3 1 1 2]
		 */
		for (col = 0; col < 4; col++) {
			a = s[4 * col + 0];
			b = s[4 * col + 1];
			c = s[4 * col + 2];
			d = s[4 * col + 3];
			s[4 * col + 0] = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d;
			s[4 * col + 1] = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d;
			s[4 * col + 2] = a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
			s[4 * col + 3] = (xtime(a) ^ a) ^ b ^ c ^ xtime(d);
		}

		add_round_key(s, rk, round * 4);
	}

	/* Final round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
	for (col = 0; col < 16; col++)
		s[col] = sbox[s[col]];

	shift_rows(s);
	add_round_key(s, rk, 40);

	memcpy(out, s, 16);
}
