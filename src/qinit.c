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

/* QUIC variable-length integer (RFC 9000 §16).
 * Writes 1, 2, 4, or 8 bytes to p; returns pointer past the end.
 */
static u8 *qinit_put_varint(u8 *p, u64 v)
{
	if (v <= 63) {
		*p++ = (u8)v;
	} else if (v <= 16383) {
		*p++ = (u8)(0x40 | (v >> 8));
		*p++ = (u8)v;
	} else if (v <= 1073741823) {
		*p++ = (u8)(0x80 | (v >> 24));
		*p++ = (u8)(v >> 16);
		*p++ = (u8)(v >>  8);
		*p++ = (u8)v;
	} else {
		*p++ = (u8)(0xc0 | (v >> 56));
		*p++ = (u8)(v >> 48);
		*p++ = (u8)(v >> 40);
		*p++ = (u8)(v >> 32);
		*p++ = (u8)(v >> 24);
		*p++ = (u8)(v >> 16);
		*p++ = (u8)(v >>  8);
		*p++ = (u8)v;
	}
	return p;
}

/* TLS vector helpers (big-endian length prefix).
 * Each returns pointer past the last written byte.
 */

/* u8-length-prefixed vector: 1-byte len || body */
static u8 *qinit_put_u8vec(u8 *p, const u8 *body, u32 blen)
{
	*p++ = (u8)blen;
	if (blen)
		memcpy(p, body, blen);
	return p + blen;
}

/* u16-length-prefixed vector: 2-byte BE len || body */
static u8 *qinit_put_u16vec(u8 *p, const u8 *body, u32 blen)
{
	*p++ = (u8)(blen >> 8);
	*p++ = (u8)blen;
	if (blen)
		memcpy(p, body, blen);
	return p + blen;
}

/* TLS extension: u16 type || u16-vec(data) */
static u8 *qinit_put_ext(u8 *p, u16 etype, const u8 *data, u32 dlen)
{
	*p++ = (u8)(etype >> 8);
	*p++ = (u8)etype;
	return qinit_put_u16vec(p, data, dlen);
}

/* TLS 1.3 ClientHello handshake message (direct port of
 * buildClientHelloWithRand from obf_imitate_quic.go).
 *
 * Buffer layout (all within the 512-byte scratch on the stack):
 *   exts[]  - assembled extension block
 *   body[]  - ClientHello body
 *   out[]   - caller-provided; handshake type(1)+len(3)+body written
 *
 * Draw order (load-bearing, matches Go oracle):
 *   rand(pub, 32)    - key_share public key
 *   rand(random, 32) - ClientHello random
 *
 * Returns bytes written into out, or -1 if sni is too long.
 */
static int __maybe_unused
qinit_build_client_hello(u8 *out, const char *sni,
			 const u8 *scid, u32 scidlen,
			 qinit_rand_fn rand, void *rctx)
{
	/* Extension scratch: max ~512 bytes (well within stack budget). */
	u8 exts[512];
	u8 body[512];
	u8 *ep = exts; /* extension write pointer */
	u8 *bp = body; /* body write pointer      */
	u8 *op = out;  /* output write pointer    */
	u32 snilen, extlen, bodylen;

	/* Scratch buffers for extension sub-structures. */
	u8 sni_list[3 + 255]; /* 0x00 | u16 len | name */
	u8 qtp[2 + 20];       /* 0x0f | scidlen | scid  */
	u8 pub[32];
	u8 random[32];
	u32 sni_list_len;

	snilen = 0;
	while (sni[snilen])
		snilen++;
	if (snilen > 255 || snilen == 0)
		return -1;

	/* Draw randomness in Go-oracle order: pub first, then random. */
	rand(rctx, pub, 32);
	rand(rctx, random, 32);

	/* --- Build extensions in Go-oracle order --- */

	/* server_name (0x0000): server_name_list{ host_name(0x00) | u16 len | sni } */
	sni_list[0] = 0x00;
	sni_list[1] = (u8)(snilen >> 8);
	sni_list[2] = (u8)snilen;
	memcpy(sni_list + 3, sni, snilen);
	sni_list_len = 3 + snilen;
	{
		u8 wrapped[2 + 3 + 255];
		u8 *wp = wrapped;

		wp = qinit_put_u16vec(wp, sni_list, sni_list_len);
		ep = qinit_put_ext(ep, 0x0000, wrapped, (u32)(wp - wrapped));
	}

	/* supported_versions (0x002b): u8-vec of [0x03, 0x04] */
	{
		const u8 sv_body[] = {0x03, 0x04};
		u8 sv[1 + 2];
		u8 *sp = sv;

		sp = qinit_put_u8vec(sp, sv_body, sizeof(sv_body));
		ep = qinit_put_ext(ep, 0x002b, sv, (u32)(sp - sv));
	}

	/* supported_groups (0x000a): u16-vec of [0x00, 0x1d] (x25519) */
	{
		const u8 sg_body[] = {0x00, 0x1d};
		u8 sg[2 + 2];
		u8 *sp = sg;

		sp = qinit_put_u16vec(sp, sg_body, sizeof(sg_body));
		ep = qinit_put_ext(ep, 0x000a, sg, (u32)(sp - sg));
	}

	/* key_share (0x0033): u16-vec of { group 0x001d | u16 len | 32-byte pub } */
	{
		u8 ks_inner[2 + 2 + 32]; /* group | u16 len | pub */
		u8 *kp = ks_inner;
		u8 ks_outer[2 + sizeof(ks_inner)];
		u8 *ko = ks_outer;

		*kp++ = 0x00; *kp++ = 0x1d;          /* x25519 group */
		kp = qinit_put_u16vec(kp, pub, 32);   /* key_exchange */
		ko = qinit_put_u16vec(ko, ks_inner, (u32)(kp - ks_inner));
		ep = qinit_put_ext(ep, 0x0033, ks_outer, (u32)(ko - ks_outer));
	}

	/* signature_algorithms (0x000d): u16-vec [0x0403, 0x0804, 0x0401] */
	{
		const u8 sa_body[] = {0x04, 0x03, 0x08, 0x04, 0x04, 0x01};
		u8 sa[2 + 6];
		u8 *sp = sa;

		sp = qinit_put_u16vec(sp, sa_body, sizeof(sa_body));
		ep = qinit_put_ext(ep, 0x000d, sa, (u32)(sp - sa));
	}

	/* application_layer_protocol_negotiation (0x0010): u16-vec(u8-vec("h3")) */
	{
		const u8 h3[] = {'h', '3'};
		u8 alpn_inner[1 + 2]; /* u8-vec("h3") */
		u8 alpn_outer[2 + sizeof(alpn_inner)];
		u8 *ai = alpn_inner;
		u8 *ao = alpn_outer;

		ai = qinit_put_u8vec(ai, h3, sizeof(h3));
		ao = qinit_put_u16vec(ao, alpn_inner, (u32)(ai - alpn_inner));
		ep = qinit_put_ext(ep, 0x0010, alpn_outer, (u32)(ao - alpn_outer));
	}

	/* quic_transport_parameters (0x0039):
	 * initial_source_connection_id (0x0f) = [0x0f, scidlen, scid...]
	 */
	{
		u32 qtplen = 2 + scidlen;
		u8 *qp = qtp;

		*qp++ = 0x0f;
		*qp++ = (u8)scidlen;
		memcpy(qp, scid, scidlen);
		ep = qinit_put_ext(ep, 0x0039, qtp, qtplen);
	}

	extlen = (u32)(ep - exts);

	/* --- Build ClientHello body --- */
	*bp++ = 0x03; *bp++ = 0x03;      /* legacy_version = TLS 1.2 */
	memcpy(bp, random, 32); bp += 32; /* random */
	bp = qinit_put_u8vec(bp, NULL, 0); /* legacy_session_id: empty */
	{
		const u8 cs[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};

		bp = qinit_put_u16vec(bp, cs, sizeof(cs)); /* cipher_suites */
	}
	{
		const u8 comp[] = {0x00};

		bp = qinit_put_u8vec(bp, comp, sizeof(comp)); /* compression */
	}
	bp = qinit_put_u16vec(bp, exts, extlen); /* extensions */

	bodylen = (u32)(bp - body);

	/* --- Handshake wrapper: 0x01 + u24 length + body --- */
	*op++ = 0x01;
	*op++ = (u8)(bodylen >> 16);
	*op++ = (u8)(bodylen >>  8);
	*op++ = (u8)bodylen;
	memcpy(op, body, bodylen);
	op += bodylen;

	return (int)(op - out);
}

/* QUIC CRYPTO frame (RFC 9001 §17.2.2):
 *   varint(0x06) + varint(offset=0) + varint(len) + data
 *
 * Returns bytes written into out.
 */
static int __maybe_unused
qinit_build_crypto_frame(u8 *out, const u8 *ch, int chlen)
{
	u8 *p = out;

	p = qinit_put_varint(p, 0x06);          /* type  */
	p = qinit_put_varint(p, 0);             /* offset */
	p = qinit_put_varint(p, (u64)chlen);    /* length */
	memcpy(p, ch, (u32)chlen);
	p += chlen;
	return (int)(p - out);
}

/* Test-only shim (userspace / KAT only). */
#ifndef __KERNEL__
int qinit_test_put_varint(u8 *out, u64 v)
{
	return (int)(qinit_put_varint(out, v) - out);
}
#endif

/* qinit_build — build a QINIT_DATAGRAM_LEN-byte QUIC v1 Initial datagram
 * carrying a TLS 1.3 ClientHello advertising `sni`, into buf.
 *
 * Port of buildQUICInitialWithRand (obf_imitate_quic.go).  Fixed datagram
 * length 1200, pnLen = 4.
 *
 * Draw order (load-bearing, matches Go oracle):
 *   rand(dcid, 8), rand(scid, 8), rand(pn, 4),
 *   then rand(pub, 32), rand(random, 32) inside qinit_build_client_hello.
 *
 * Stack budget for this frame (no heap):
 *   dcid[8]+scid[8]+pn[4]=20, key[16]+iv[12]+hp[16]=44, nonce[12]=12,
 *   ch[512]=512 (CH scratch), chlen(4)+cflen(4)=8 — total ~600 B < 2048.
 *   The called qinit_build_client_hello frame is separate (~1100 B < 2048).
 */
int qinit_build(u8 *buf, const char *sni, qinit_rand_fn rand, void *rctx)
{
	u8 dcid[8], scid[8], pn[4];
	u8 key[16], iv[12], hp[16];
	u8 nonce[12];
	u8 ch[512];   /* ClientHello handshake message scratch */
	int chlen, cflen;
	u8 *p;
	int pnOffset;
	u8 sample[16], mask[16];
	struct aes128_ctx hp_ctx;

	/* Draw order: dcid, scid, pn (then CH draws pub+random internally). */
	rand(rctx, dcid, 8);
	rand(rctx, scid, 8);
	rand(rctx, pn,   4);

	/* Derive client Initial keys from DCID. */
	qinit_derive_initial_keys(dcid, 8, key, iv, hp);

	/* Build ClientHello handshake message (draws pub+random via rand). */
	chlen = qinit_build_client_hello(ch, sni, scid, 8, rand, rctx);
	if (chlen < 0)
		return -22; /* -EINVAL */

	/*
	 * Layout (fixed, 1200 bytes):
	 *   headerLen = 1+4+1+8+1+8+1+2+4 = 30
	 *   payloadLen = 1200 - 30 - 16 = 1154  (16 = GCM tag)
	 *   lengthField = pnLen(4) + payloadLen(1154) + 16 = 1174 (varint 0x4496)
	 */
	p = buf;

	/* Byte 0: long-header | fixed | Initial(00) | reserved(00) | pnLen-1=3 */
	*p++ = 0xC3u;

	/* Version: 0x00000001 */
	*p++ = 0x00u; *p++ = 0x00u; *p++ = 0x00u; *p++ = 0x01u;

	/* DCID: u8 len + dcid */
	*p++ = 8u;
	memcpy(p, dcid, 8); p += 8;

	/* SCID: u8 len + scid */
	*p++ = 8u;
	memcpy(p, scid, 8); p += 8;

	/* Token: length 0x00 */
	*p++ = 0x00u;

	/* Length field: varint(1174 = 0x4496) */
	p = qinit_put_varint(p, 1174u);

	/* Record pnOffset and write PN. */
	pnOffset = (int)(p - buf); /* = 26 */
	memcpy(p, pn, 4); p += 4;
	/* p is now at buf + 30 = headerLen */

	/* Write CRYPTO frame + CH into payload region of buf, then zero-pad.
	 * cflen = CRYPTO frame header (type+offset+length varints) + chlen.
	 */
	{
		u8 *payload = buf + 30;
		u8 *fp = payload;

		/* CRYPTO frame: type 0x06, offset 0, length chlen */
		fp = qinit_put_varint(fp, 0x06u);
		fp = qinit_put_varint(fp, 0u);
		fp = qinit_put_varint(fp, (u64)chlen);
		memcpy(fp, ch, (u32)chlen);
		fp += chlen;
		cflen = (int)(fp - payload);

		/* Zero-pad to payloadLen (1154) — trailing 0x00 = PADDING frames. */
		if (cflen < 1154)
			memset(payload + cflen, 0, (u32)(1154 - cflen));
	}

	/* Nonce: iv XOR pn (XOR into the last 4 bytes, indices 8..11). */
	memcpy(nonce, iv, 12);
	nonce[8]  ^= pn[0];
	nonce[9]  ^= pn[1];
	nonce[10] ^= pn[2];
	nonce[11] ^= pn[3];

	/* AEAD seal in place: plaintext is buf[30..30+1153], output overwrites it
	 * and the 16-byte tag lands at buf[30+1154..30+1169].
	 * AAD = header bytes buf[0..29].
	 * qinit_aes128_gcm_seal(key, nonce, aad, aadlen, pt, ptlen, out):
	 *   out must hold ptlen+16 bytes; we pass buf+30 which holds 1154+16=1170.
	 */
	qinit_aes128_gcm_seal(key, nonce, buf, 30u, buf + 30, 1154u, buf + 30);

	/* Header protection: sample = buf[pnOffset+4 .. pnOffset+4+15] */
	memcpy(sample, buf + pnOffset + 4, 16);
	aes128_set_encrypt_key(&hp_ctx, hp);
	aes128_encrypt_block(&hp_ctx, sample, mask);

	/* Mask byte0 (low 4 bits) and each PN byte. */
	buf[0] ^= mask[0] & 0x0fu;
	buf[pnOffset + 0] ^= mask[1];
	buf[pnOffset + 1] ^= mask[2];
	buf[pnOffset + 2] ^= mask[3];
	buf[pnOffset + 3] ^= mask[4];

	return 0;
}

#ifdef __KERNEL__
void qinit_rand_getrandom(void *rctx, u8 *out, int n)
{
	(void)rctx;
	get_random_bytes(out, n);
}
#endif
