// SPDX-License-Identifier: GPL-2.0
/*
 * SHA-256 — FIPS-180-4, hash-only.
 * No constant-time requirement: qinit usage is over public data.
 */
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "sha256.h"

/* FIPS-180-4 §4.2.2: first 32 bits of fractional parts of cube roots of
 * first 64 primes.
 */
static const u32 K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* FIPS-180-4 §5.3.3: initial hash values (first 32 bits of fractional parts
 * of square roots of first 8 primes).
 */
static const u32 H0[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static u32 rotr32(u32 x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

/* FIPS-180-4 §4.1.2 */
static u32 ch(u32 e, u32 f, u32 g)
{
	return (e & f) ^ (~e & g);
}

static u32 maj(u32 a, u32 b, u32 c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

/* Σ0, Σ1, σ0, σ1 — FIPS-180-4 §4.1.2 */
static u32 bsig0(u32 x)
{
	return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static u32 bsig1(u32 x)
{
	return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static u32 ssig0(u32 x)
{
	return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static u32 ssig1(u32 x)
{
	return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

/* Hand-rolled big-endian load/store (no cpu_to_be* / htons). */
static u32 load_be32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] <<  8) |  (u32)p[3];
}

static void store_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >>  8);
	p[3] = (u8)(v);
}

static void store_be64(u8 *p, u64 v)
{
	p[0] = (u8)(v >> 56);
	p[1] = (u8)(v >> 48);
	p[2] = (u8)(v >> 40);
	p[3] = (u8)(v >> 32);
	p[4] = (u8)(v >> 24);
	p[5] = (u8)(v >> 16);
	p[6] = (u8)(v >>  8);
	p[7] = (u8)(v);
}

/* Compress one 64-byte block into ctx->h[0..7]. */
static void sha256_compress(struct sha256_ctx *ctx, const u8 block[SHA256_BLOCK_LEN])
{
	u32 w[64];
	u32 a, b, c, d, e, f, g, h;
	u32 t1, t2;
	int i;

	/* Message schedule (FIPS-180-4 §6.2.2 step 1) */
	for (i = 0; i < 16; i++)
		w[i] = load_be32(block + 4 * i);
	for (i = 16; i < 64; i++)
		w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];

	/* Initialize working variables (step 2) */
	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	/* 64 rounds (step 3) */
	for (i = 0; i < 64; i++) {
		t1 = h + bsig1(e) + ch(e, f, g) + K[i] + w[i];
		t2 = bsig0(a) + maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	/* Compute new hash value (step 4) */
	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

void sha256_init(struct sha256_ctx *ctx)
{
	int i;

	for (i = 0; i < 8; i++)
		ctx->h[i] = H0[i];
	ctx->len = 0;
	ctx->buflen = 0;
}

void sha256_update(struct sha256_ctx *ctx, const u8 *data, u32 len)
{
	u32 left;

	ctx->len += len;

	while (len > 0) {
		left = SHA256_BLOCK_LEN - ctx->buflen;
		if (len < left) {
			memcpy(ctx->buf + ctx->buflen, data, len);
			ctx->buflen += len;
			return;
		}
		memcpy(ctx->buf + ctx->buflen, data, left);
		sha256_compress(ctx, ctx->buf);
		ctx->buflen = 0;
		data += left;
		len  -= left;
	}
}

void sha256_final(struct sha256_ctx *ctx, u8 out[SHA256_DIGEST_LEN])
{
	u64 bitlen = ctx->len * 8;
	int i;

	/* FIPS-180-4 §5.1.1: append 0x80 byte. */
	ctx->buf[ctx->buflen++] = 0x80;

	/*
	 * If there is not enough room for the 8-byte big-endian bit-length
	 * field, zero-pad to a full block, compress it, and start a fresh
	 * padding block.
	 */
	if (ctx->buflen > 56) {
		memset(ctx->buf + ctx->buflen, 0,
		       SHA256_BLOCK_LEN - ctx->buflen);
		sha256_compress(ctx, ctx->buf);
		ctx->buflen = 0;
	}

	/* Zero-pad bytes [buflen..55], then write 64-bit bit-length at [56..63]. */
	memset(ctx->buf + ctx->buflen, 0, 56 - ctx->buflen);
	store_be64(ctx->buf + 56, bitlen);
	sha256_compress(ctx, ctx->buf);

	/* Produce big-endian digest. */
	for (i = 0; i < 8; i++)
		store_be32(out + 4 * i, ctx->h[i]);
}

void sha256(const u8 *data, u32 len, u8 out[SHA256_DIGEST_LEN])
{
	struct sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, out);
}
