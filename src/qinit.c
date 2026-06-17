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
