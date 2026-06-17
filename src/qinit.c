// SPDX-License-Identifier: GPL-2.0
#include "qinit.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/random.h>
#else
#include <string.h>
#endif

/* GF(2^128) multiply Z by V (MSB-first bit order, reduction poly x^128+x^7+x^2+x+1).
 * R = 0xe1 << 120 in the field representation.  No constant-time requirement.
 */
static void gcm_gmul(u8 z[16], const u8 v[16])
{
	u8 result[16] = {0};
	u8 vtmp[16];
	int i, bit;

	memcpy(vtmp, v, 16);
	for (i = 0; i < 16; i++) {
		for (bit = 7; bit >= 0; bit--) {
			if (z[i] & (1u << bit)) {
				int j;

				for (j = 0; j < 16; j++)
					result[j] ^= vtmp[j];
			}
			/* Right-shift vtmp by 1 bit in GF(2^128) MSB-first order. */
			{
				u8 carry = 0;
				int j;

				/* Check LSB of vtmp before shift (becomes the carry). */
				carry = vtmp[15] & 1u;
				for (j = 15; j > 0; j--)
					vtmp[j] = (vtmp[j] >> 1) | ((vtmp[j - 1] & 1u) << 7);
				vtmp[0] >>= 1;
				/* If carry was 1, XOR with reduction polynomial R. */
				if (carry)
					vtmp[0] ^= 0xe1u;
			}
		}
	}
	memcpy(z, result, 16);
}

/* GHASH: accumulate one 16-byte block into the running hash state. */
static void ghash_update(u8 state[16], const u8 block[16], const u8 h[16])
{
	int i;

	for (i = 0; i < 16; i++)
		state[i] ^= block[i];
	gcm_gmul(state, h);
}

/* GHASH over an arbitrary-length byte stream (zero-padded to 16-byte boundary). */
static void ghash_data(u8 state[16], const u8 *data, u32 len, const u8 h[16])
{
	u8 block[16];
	u32 i;

	while (len >= 16) {
		ghash_update(state, data, h);
		data += 16;
		len  -= 16;
	}
	if (len > 0) {
		memset(block, 0, 16);
		for (i = 0; i < len; i++)
			block[i] = data[i];
		ghash_update(state, block, h);
	}
}

/* Increment the 32-bit counter (bytes 12–15 of a 16-byte counter block), big-endian. */
static void gcm_inc32(u8 ctr[16])
{
	u32 c;

	c  = (u32)ctr[12] << 24 | (u32)ctr[13] << 16 | (u32)ctr[14] << 8 | ctr[15];
	c++;
	ctr[12] = (u8)(c >> 24);
	ctr[13] = (u8)(c >> 16);
	ctr[14] = (u8)(c >>  8);
	ctr[15] = (u8)c;
}

void qinit_aes128_gcm_seal(const u8 key[16], const u8 nonce[12],
			   const u8 *aad, u32 aadlen,
			   const u8 *pt, u32 ptlen, u8 *out)
{
	struct aes128_ctx ctx;
	u8 h[16]     = {0};  /* H = AES_K(0^128)    */
	u8 j0[16]    = {0};  /* J0 counter block     */
	u8 ctr[16]   = {0};  /* running CTR block    */
	u8 ks[16]    = {0};  /* keystream block      */
	u8 ghash[16] = {0};  /* GHASH accumulator    */
	u8 lenbuf[16];       /* len(A)||len(C) block */
	u32 i;

	aes128_set_encrypt_key(&ctx, key);

	/* H = AES_K(0^128) */
	aes128_encrypt_block(&ctx, h, h);

	/* J0 = nonce(12) || 0x00000001 */
	memcpy(j0, nonce, 12);
	j0[15] = 0x01u;

	/* CTR encrypt: start from inc32(J0), i.e. counter = 2 for first PT block. */
	memcpy(ctr, j0, 16);
	gcm_inc32(ctr);

	for (i = 0; i < ptlen; i++) {
		if (i % 16 == 0) {
			aes128_encrypt_block(&ctx, ctr, ks);
			gcm_inc32(ctr);
		}
		out[i] = pt[i] ^ ks[i % 16];
	}

	/* GHASH over AAD (zero-padded), then CT (zero-padded), then lengths. */
	ghash_data(ghash, aad, aadlen, h);
	ghash_data(ghash, out, ptlen, h);

	/* Length block: len(AAD) and len(CT) in bits, each as 64-bit big-endian. */
	{
		u64 abits = (u64)aadlen * 8;
		u64 cbits = (u64)ptlen  * 8;

		lenbuf[0]  = (u8)(abits >> 56);
		lenbuf[1]  = (u8)(abits >> 48);
		lenbuf[2]  = (u8)(abits >> 40);
		lenbuf[3]  = (u8)(abits >> 32);
		lenbuf[4]  = (u8)(abits >> 24);
		lenbuf[5]  = (u8)(abits >> 16);
		lenbuf[6]  = (u8)(abits >>  8);
		lenbuf[7]  = (u8)abits;
		lenbuf[8]  = (u8)(cbits >> 56);
		lenbuf[9]  = (u8)(cbits >> 48);
		lenbuf[10] = (u8)(cbits >> 40);
		lenbuf[11] = (u8)(cbits >> 32);
		lenbuf[12] = (u8)(cbits >> 24);
		lenbuf[13] = (u8)(cbits >> 16);
		lenbuf[14] = (u8)(cbits >>  8);
		lenbuf[15] = (u8)cbits;
	}
	ghash_update(ghash, lenbuf, h);

	/* tag = GHASH XOR AES_K(J0); append after ciphertext. */
	aes128_encrypt_block(&ctx, j0, ks);
	for (i = 0; i < 16; i++)
		out[ptlen + i] = ghash[i] ^ ks[i];
}

void qinit_hmac_sha256(const u8 *key, u32 klen, const u8 *msg, u32 mlen, u8 out[32])
{
	u8 k[SHA256_BLOCK_LEN] = {0};
	u8 ipad[SHA256_BLOCK_LEN], opad[SHA256_BLOCK_LEN];
	u8 inner[SHA256_DIGEST_LEN];
	struct sha256_ctx c;
	int i;

	if (klen > SHA256_BLOCK_LEN)
		sha256(key, klen, k);          /* hashed key fits in 32 of the 64 zero bytes */
	else
		memcpy(k, key, klen);

	for (i = 0; i < SHA256_BLOCK_LEN; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	sha256_init(&c);
	sha256_update(&c, ipad, SHA256_BLOCK_LEN);
	sha256_update(&c, msg, mlen);
	sha256_final(&c, inner);

	sha256_init(&c);
	sha256_update(&c, opad, SHA256_BLOCK_LEN);
	sha256_update(&c, inner, SHA256_DIGEST_LEN);
	sha256_final(&c, out);
}

/* RFC 5869 §2.2. NOTE: salt is the HMAC *key*, ikm is the message. */
void qinit_hkdf_extract(const u8 *salt, u32 slen, const u8 *ikm, u32 ilen, u8 prk[32])
{
	qinit_hmac_sha256(salt, slen, ikm, ilen, prk);
}

/* RFC 9001 §5.2 client Initial key derivation. The salt is the HMAC *key* and
 * the DCID is the IKM (initial_secret = HMAC(key=salt, msg=dcid)) — the order is
 * load-bearing; the A.1 KAT only passes if it is correct.
 */
static const u8 quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

void qinit_derive_initial_keys(const u8 *dcid, u32 dcidlen,
			       u8 key[16], u8 iv[12], u8 hp[16])
{
	u8 initial_secret[32], client_secret[32];

	qinit_hkdf_extract(quic_v1_initial_salt, sizeof(quic_v1_initial_salt),
			   dcid, dcidlen, initial_secret);
	qinit_hkdf_expand_label(initial_secret, "client in", client_secret, 32);
	qinit_hkdf_expand_label(client_secret, "quic key", key, 16);
	qinit_hkdf_expand_label(client_secret, "quic iv", iv, 12);
	qinit_hkdf_expand_label(client_secret, "quic hp", hp, 16);
}

/* TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with "tls13 " prefix + zero-length
 * context, built on HKDF-Expand (RFC 5869 §2.3). len <= 32 for all qinit uses
 * (key 16 / iv 12 / hp 16 / client-secret 32), so a single HMAC block (T(1))
 * suffices — assert and handle exactly that.
 */
void qinit_hkdf_expand_label(const u8 *secret, const char *label, u8 *out, u16 len)
{
	u8 full[6 + 32];          /* "tls13 " + label (labels here are <= ~9 chars) */
	u8 info[2 + 1 + sizeof(full) + 1];
	u8 t[SHA256_DIGEST_LEN];
	u32 fl, il, i;

	fl = 6;
	memcpy(full, "tls13 ", 6);
	for (i = 0; label[i]; i++)
		full[fl++] = (u8)label[i];

	il = 0;
	info[il++] = (u8)(len >> 8);   /* uint16 length, big-endian */
	info[il++] = (u8)len;
	info[il++] = (u8)fl;           /* label vector length (u8) */
	memcpy(info + il, full, fl);
	il += fl;
	info[il++] = 0x00;             /* zero-length context */

	/* T(1) = HMAC(secret, T(0) | info | 0x01); T(0) empty. len <= 32 always. */
	{
		u8 m[sizeof(info) + 1];

		memcpy(m, info, il);
		m[il] = 0x01;
		qinit_hmac_sha256(secret, SHA256_DIGEST_LEN, m, il + 1, t);
	}
	memcpy(out, t, len);
}
