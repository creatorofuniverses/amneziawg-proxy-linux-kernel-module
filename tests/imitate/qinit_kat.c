// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "imitate_shim.h"
#include "../../src/crypto/aes.h"
#include "../../src/crypto/sha256.h"
#include "../../src/qinit.h"

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

/* FIPS-180-4 / NIST CAVP. */
static void test_sha256(void)
{
	u8 out[32];
	/* "abc" */
	const u8 want_abc[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	/* "" (empty) */
	const u8 want_empty[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	sha256((const u8 *)"abc", 3, out);
	eq("sha256_abc", out, want_abc, 32);
	sha256((const u8 *)"", 0, out);
	eq("sha256_empty", out, want_empty, 32);
}

/* RFC 4231 test case 1. */
static void test_hmac_sha256(void)
{
	u8 key[20], out[32];
	const u8 want[32] = {
		0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
		0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
	memset(key, 0x0b, sizeof(key));
	qinit_hmac_sha256(key, sizeof(key), (const u8 *)"Hi There", 8, out);
	eq("hmac_sha256_rfc4231_1", out, want, 32);
}

/* RFC 5869 Appendix A.1 (SHA-256): Extract then Expand. Expand here uses the raw
 * RFC info, so test it via qinit_hkdf_extract + a direct expand check below. */
static void test_hkdf_extract(void)
{
	const u8 ikm[22] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
			    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
	const u8 salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
	const u8 want_prk[32] = {
		0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
		0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5};
	u8 prk[32];
	qinit_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
	eq("hkdf_extract_rfc5869", prk, want_prk, 32);
}

/* GCM spec (McGrew & Viega) Test Case 4: AES-128, 96-bit IV, AAD present. */
static void test_aes128_gcm(void)
{
	const u8 key[16]   = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
			      0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
	const u8 nonce[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
	const u8 aad[20]   = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,
			      0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2};
	const u8 pt[60] = {
		0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
		0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
		0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
		0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39};
	/* Expected ciphertext (60) then tag (16) — GCM spec Test Case 4. */
	const u8 want[76] = {
		0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
		0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
		0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
		0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,
		0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47};
	u8 out[76];

	qinit_aes128_gcm_seal(key, nonce, aad, sizeof(aad), pt, sizeof(pt), out);
	eq("aes128_gcm_tc4", out, want, sizeof(want));
}

/* Harness-local LCG PRNG (Knuth multiplicative, 32-bit) — distinct from
 * production; only decodability is asserted, not specific bytes.
 */
struct lcgrand { u32 s; };
static void lcgrand_fn(void *rctx, u8 *out, int n)
{
	struct lcgrand *lr = rctx;
	int i;

	for (i = 0; i < n; i++) {
		lr->s = lr->s * 1664525u + 1013904223u;
		out[i] = (u8)(lr->s >> 24);
	}
}

/* Deterministic rand source: sequential replay of a fixed buffer. */
struct fixedrand { const u8 *p; int n, off; };
static void fixedrand_fn(void *rctx, u8 *out, int n)
{
	struct fixedrand *fr = rctx;
	int i;

	for (i = 0; i < n; i++)
		out[i] = (fr->off < fr->n) ? fr->p[fr->off++] : 0;
}

static int read_file(const char *path, u8 *buf, int max)
{
	FILE *f = fopen(path, "rb");
	int n;

	if (!f)
		return -1;
	n = (int)fread(buf, 1, max, f);
	fclose(f);
	return n;
}

/* Harness-local AES-128-GCM open (CTR decrypt + GHASH tag verify).
 * Returns 1 if tag is valid, 0 on auth failure.
 * ct contains the ciphertext (ctlen bytes) followed by the 16-byte tag.
 * pt receives the ctlen decrypted bytes.
 */
static int aes128_gcm_open(const u8 key[16], const u8 nonce[12],
			   const u8 *aad, u32 aadlen,
			   const u8 *ct, u32 ctlen, u8 *pt)
{
	struct aes128_ctx ctx;
	u8 h[16]     = {0};
	u8 j0[16]    = {0};
	u8 ctr[16]   = {0};
	u8 ks[16]    = {0};
	u8 ghash[16] = {0};
	u8 lenbuf[16];
	u8 tag_calc[16], tag_enc[16];
	u32 i;

	aes128_set_encrypt_key(&ctx, key);
	aes128_encrypt_block(&ctx, h, h);

	memcpy(j0, nonce, 12);
	j0[15] = 0x01u;

	/* GHASH over AAD then CT. */
	{
		u8 blk[16];
		const u8 *p = aad;
		u32 rem = aadlen;

		while (rem >= 16) {
			for (i = 0; i < 16; i++) ghash[i] ^= p[i];
			/* GF multiply - reuse same logic as seal */
			{
				u8 z[16]; u8 v[16]; u8 res[16] = {0};
				int b; u8 carry;

				memcpy(z, ghash, 16);
				memcpy(v, h, 16);
				for (i = 0; i < 16; i++) {
					for (b = 7; b >= 0; b--) {
						int j;

						if (z[i] & (1u << b))
							for (j = 0; j < 16; j++) res[j] ^= v[j];
						carry = v[15] & 1u;
						for (j = 15; j > 0; j--)
							v[j] = (v[j] >> 1) | ((v[j-1] & 1u) << 7);
						v[0] >>= 1;
						if (carry) v[0] ^= 0xe1u;
					}
				}
				memcpy(ghash, res, 16);
			}
			p += 16; rem -= 16;
		}
		if (rem > 0) {
			memset(blk, 0, 16);
			for (i = 0; i < rem; i++) blk[i] = p[i];
			for (i = 0; i < 16; i++) ghash[i] ^= blk[i];
			{
				u8 z[16]; u8 v[16]; u8 res[16] = {0};
				int b; u8 carry;

				memcpy(z, ghash, 16);
				memcpy(v, h, 16);
				for (i = 0; i < 16; i++) {
					for (b = 7; b >= 0; b--) {
						int j;

						if (z[i] & (1u << b))
							for (j = 0; j < 16; j++) res[j] ^= v[j];
						carry = v[15] & 1u;
						for (j = 15; j > 0; j--)
							v[j] = (v[j] >> 1) | ((v[j-1] & 1u) << 7);
						v[0] >>= 1;
						if (carry) v[0] ^= 0xe1u;
					}
				}
				memcpy(ghash, res, 16);
			}
		}
	}

	{
		const u8 *p = ct;
		u32 rem = ctlen;

		while (rem >= 16) {
			for (i = 0; i < 16; i++) ghash[i] ^= p[i];
			{
				u8 z[16]; u8 v[16]; u8 res[16] = {0};
				int b; u8 carry;

				memcpy(z, ghash, 16);
				memcpy(v, h, 16);
				for (i = 0; i < 16; i++) {
					for (b = 7; b >= 0; b--) {
						int j;

						if (z[i] & (1u << b))
							for (j = 0; j < 16; j++) res[j] ^= v[j];
						carry = v[15] & 1u;
						for (j = 15; j > 0; j--)
							v[j] = (v[j] >> 1) | ((v[j-1] & 1u) << 7);
						v[0] >>= 1;
						if (carry) v[0] ^= 0xe1u;
					}
				}
				memcpy(ghash, res, 16);
			}
			p += 16; rem -= 16;
		}
		if (rem > 0) {
			u8 blk[16];

			memset(blk, 0, 16);
			for (i = 0; i < rem; i++) blk[i] = p[i];
			for (i = 0; i < 16; i++) ghash[i] ^= blk[i];
			{
				u8 z[16]; u8 v[16]; u8 res[16] = {0};
				int b; u8 carry;

				memcpy(z, ghash, 16);
				memcpy(v, h, 16);
				for (i = 0; i < 16; i++) {
					for (b = 7; b >= 0; b--) {
						int j;

						if (z[i] & (1u << b))
							for (j = 0; j < 16; j++) res[j] ^= v[j];
						carry = v[15] & 1u;
						for (j = 15; j > 0; j--)
							v[j] = (v[j] >> 1) | ((v[j-1] & 1u) << 7);
						v[0] >>= 1;
						if (carry) v[0] ^= 0xe1u;
					}
				}
				memcpy(ghash, res, 16);
			}
		}
	}

	{
		u64 abits = (u64)aadlen * 8;
		u64 cbits = (u64)ctlen  * 8;

		lenbuf[0]  = (u8)(abits >> 56); lenbuf[1]  = (u8)(abits >> 48);
		lenbuf[2]  = (u8)(abits >> 40); lenbuf[3]  = (u8)(abits >> 32);
		lenbuf[4]  = (u8)(abits >> 24); lenbuf[5]  = (u8)(abits >> 16);
		lenbuf[6]  = (u8)(abits >>  8); lenbuf[7]  = (u8)abits;
		lenbuf[8]  = (u8)(cbits >> 56); lenbuf[9]  = (u8)(cbits >> 48);
		lenbuf[10] = (u8)(cbits >> 40); lenbuf[11] = (u8)(cbits >> 32);
		lenbuf[12] = (u8)(cbits >> 24); lenbuf[13] = (u8)(cbits >> 16);
		lenbuf[14] = (u8)(cbits >>  8); lenbuf[15] = (u8)cbits;
		for (i = 0; i < 16; i++) ghash[i] ^= lenbuf[i];
		{
			u8 z[16]; u8 v[16]; u8 res[16] = {0};
			int b; u8 carry;

			memcpy(z, ghash, 16);
			memcpy(v, h, 16);
			for (i = 0; i < 16; i++) {
				for (b = 7; b >= 0; b--) {
					int j;

					if (z[i] & (1u << b))
						for (j = 0; j < 16; j++) res[j] ^= v[j];
					carry = v[15] & 1u;
					for (j = 15; j > 0; j--)
						v[j] = (v[j] >> 1) | ((v[j-1] & 1u) << 7);
					v[0] >>= 1;
					if (carry) v[0] ^= 0xe1u;
				}
			}
			memcpy(ghash, res, 16);
		}
	}

	/* tag = GHASH XOR AES_K(J0) */
	aes128_encrypt_block(&ctx, j0, tag_enc);
	for (i = 0; i < 16; i++)
		tag_calc[i] = ghash[i] ^ tag_enc[i];

	/* Compare with supplied tag (ct + ctlen). */
	{
		u8 diff = 0;

		for (i = 0; i < 16; i++)
			diff |= tag_calc[i] ^ ct[ctlen + i];
		if (diff != 0)
			return 0;
	}

	/* CTR decrypt. */
	memcpy(ctr, j0, 16);
	{
		u32 c;

		c = (u32)ctr[12] << 24 | (u32)ctr[13] << 16 | (u32)ctr[14] << 8 | ctr[15];
		c++;
		ctr[12] = (u8)(c >> 24); ctr[13] = (u8)(c >> 16);
		ctr[14] = (u8)(c >>  8); ctr[15] = (u8)c;
	}
	for (i = 0; i < ctlen; i++) {
		if (i % 16 == 0) {
			aes128_encrypt_block(&ctx, ctr, ks);
			{
				u32 c;

				c = (u32)ctr[12] << 24 | (u32)ctr[13] << 16 |
				    (u32)ctr[14] << 8 | ctr[15];
				c++;
				ctr[12] = (u8)(c >> 24); ctr[13] = (u8)(c >> 16);
				ctr[14] = (u8)(c >>  8); ctr[15] = (u8)c;
			}
		}
		pt[i] = ct[i] ^ ks[i % 16];
	}
	return 1;
}

/* Harness-local decoder: re-derive keys from the DCID in a QUIC Initial
 * header-protected packet, strip HP, AEAD-open, scan plaintext for sni.
 * Returns 1 if the SNI is found, 0 on any failure.
 * TEST-ONLY — lives in qinit_kat.c only.
 */
static int qinit_harness_decode_sni(const u8 *pkt, int pktlen, const char *sni)
{
	/* Parse Long Header: byte0(1) version(4) dcidLen(1) dcid scidLen(1) scid
	 *                    tokenLen(1) lengthVarint pn(4)
	 * Fixed layout for our packets: pnLen=4, dcidLen=8, scidLen=8.
	 */
	u8 key[16], iv[12], hp[16];
	u8 nonce[12];
	u8 work[1200]; /* mutable copy */
	const u8 *dcid;
	int pnOffset;
	u8 mask[16], sample[16];
	struct aes128_ctx hp_ctx;
	u8 pn[4];
	u8 plain[1154];
	u32 i;
	u32 snilen;

	if (pktlen < 30 + 16)
		return 0;

	memcpy(work, pkt, pktlen);
	dcid    = work + 6;  /* skip byte0(1)+version(4)+dcidLen(1) */

	/* Re-derive keys from DCID. */
	qinit_derive_initial_keys(dcid, 8, key, iv, hp);

	/* Compute HP mask from sample = pkt[pnOffset+4..+16].
	 * pnOffset is at 26 (before HP removal, the PN is at byte 26).
	 * sample is at pnOffset+4 = 30.
	 */
	pnOffset = 26; /* byte offset of PN in packet */
	memcpy(sample, work + pnOffset + 4, 16);
	aes128_set_encrypt_key(&hp_ctx, hp);
	aes128_encrypt_block(&hp_ctx, sample, mask);

	/* Unmask. */
	work[0] ^= mask[0] & 0x0f;
	for (i = 0; i < 4; i++)
		work[pnOffset + i] ^= mask[1 + i];

	/* Extract PN. */
	for (i = 0; i < 4; i++)
		pn[i] = work[pnOffset + i];

	/* Build nonce = iv XOR pn (last 4 bytes). */
	memcpy(nonce, iv, 12);
	for (i = 0; i < 4; i++)
		nonce[8 + i] ^= pn[i];

	/* AEAD open: AAD = header (bytes 0..pnOffset+4-1 = bytes 0..29). */
	if (!aes128_gcm_open(key, nonce, work, 30, work + 30, 1154, plain))
		return 0;

	/* Scan plain for SNI bytes. */
	snilen = 0;
	while (sni[snilen])
		snilen++;

	for (i = 0; i + snilen <= 1154; i++) {
		if (memcmp(plain + i, sni, snilen) == 0)
			return 1;
	}
	return 0;
}

static void test_golden_vector(void)
{
	u8 stream[84], want[1200], got[1200];
	struct fixedrand fr;

	if (read_file("testdata/qinit_rand.bin", stream, sizeof(stream)) != 84 ||
	    read_file("testdata/qinit_vector.bin", want, sizeof(want)) != 1200) {
		printf("FAIL golden_vector (testdata missing)\n"); fails++; return;
	}
	fr.p = stream; fr.n = 84; fr.off = 0;
	if (qinit_build(got, "example.com", fixedrand_fn, &fr) != 0) {
		printf("FAIL golden_vector (build err)\n"); fails++; return;
	}
	eq("golden_vector", got, want, 1200);
}

static void test_round_trip(void)
{
	u8 stream[84], pkt[1200];
	struct fixedrand fr;

	if (read_file("testdata/qinit_rand.bin", stream, sizeof(stream)) != 84) {
		printf("FAIL round_trip (testdata missing)\n"); fails++; return;
	}
	fr.p = stream; fr.n = 84; fr.off = 0;
	qinit_build(pkt, "example.com", fixedrand_fn, &fr);
	if (qinit_harness_decode_sni(pkt, 1200, "example.com"))
		printf("PASS round_trip\n");
	else { printf("FAIL round_trip\n"); fails++; }
}

/* QUIC variable-length integer encoding (RFC 9000 §16).
 * KAT mirrors the Go TestAppendQUICVarint cases.
 */
static void test_varint(void)
{
	struct { u64 v; const char *hex; int n; } cs[] = {
		{0, "00", 1}, {63, "3f", 1}, {1174, "4496", 2},
		{494878333, "9d7f3e7d", 4},
	};
	u8 out[8];
	char hx[20];
	unsigned i, j;
	int n;

	for (i = 0; i < sizeof(cs)/sizeof(cs[0]); i++) {
		n = qinit_test_put_varint(out, cs[i].v);
		hx[0] = 0;
		for (j = 0; j < (unsigned)n; j++)
			sprintf(hx + 2*j, "%02x", out[j]);
		if (n == cs[i].n && !strcmp(hx, cs[i].hex)) {
			printf("PASS varint_%llu\n", (unsigned long long)cs[i].v);
		} else {
			printf("FAIL varint_%llu got %s\n", (unsigned long long)cs[i].v, hx);
			fails++;
		}
	}
}

/* RFC 9001 Appendix A.1: client Initial keys for DCID 0x8394c8f03e515708. */
static void test_derive_initial_keys_rfc9001(void)
{
	const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
	const u8 wk[16] = {0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
			   0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};
	const u8 wiv[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
			    0x46, 0xfb, 0x25, 0x5c};
	const u8 whp[16] = {0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
			    0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};
	u8 key[16], iv[12], hp[16];

	qinit_derive_initial_keys(dcid, sizeof(dcid), key, iv, hp);
	eq("rfc9001_key", key, wk, 16);
	eq("rfc9001_iv", iv, wiv, 12);
	eq("rfc9001_hp", hp, whp, 16);
}

/* Layer-4 randomised property test: generate N=256 datagrams each with a
 * unique LCG seed and assert that every one decodes via the harness decoder
 * and recovers the expected SNI.  Catches varint/length edge cases that fixed
 * vectors miss.
 */
static void test_property(void)
{
	u8 pkt[1200];
	u32 s = 0x1234567u;
	int i, ok = 1;

	for (i = 0; i < 256; i++) {
		struct lcgrand lr;

		lr.s = s + (u32)i * 2654435761u;
		if (qinit_build(pkt, "example.com", lcgrand_fn, &lr) != 0) {
			ok = 0; break;
		}
		if (!qinit_harness_decode_sni(pkt, 1200, "example.com")) {
			ok = 0; break;
		}
	}
	if (ok)
		printf("PASS property_256\n");
	else {
		printf("FAIL property_256 at iter %d\n", i);
		fails++;
	}
}

int main(void)
{
	test_aes128_fips197();
	test_sha256();
	test_hmac_sha256();
	test_hkdf_extract();
	test_aes128_gcm();
	test_derive_initial_keys_rfc9001();
	test_varint();
	test_golden_vector();
	test_round_trip();
	test_property();
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
	return fails ? 1 : 0;
}
