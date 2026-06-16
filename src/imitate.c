// SPDX-License-Identifier: GPL-2.0
#include "imitate.h"

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/kernel.h>
#define IMITATE_SNPRINTF scnprintf
#else
#include <string.h>
#include <stdio.h>
#define IMITATE_SNPRINTF snprintf
#endif

static u32 lcg_step(u32 s)
{
	return s * 1103515245u + 12345u;
}

static u32 __attribute__((unused)) next_lcg(u32 *state)
{
	u32 v = *state;

	*state = lcg_step(*state);
	return v;
}

static void __attribute__((unused)) put_be16(u8 *p, u16 v)
{
	p[0] = (u8)(v >> 8);
	p[1] = (u8)v;
}

static void __attribute__((unused)) put_be32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

u32 imitate_fnv1a_seed(const u8 *payload, int len)
{
	u32 state = 0x811c9dc5u;
	int i, n = len > 64 ? 64 : len;

	for (i = 0; i < n; i++) {
		state ^= (u32)payload[i];
		state *= 0x01000193u;
	}
	return state;
}

u32 imitate_junk_seed(u64 counter)
{
	u8 b[8];
	int i;

	for (i = 0; i < 8; i++)
		b[i] = (u8)(counter >> (8 * i)); /* little-endian */
	return imitate_fnv1a_seed(b, 8);
}

enum imitate_proto imitate_proto_parse(const char *s)
{
	if (!s || !*s || !strcmp(s, "none"))
		return IMITATE_NONE;
	if (!strcmp(s, "quic"))
		return IMITATE_QUIC;
	if (!strcmp(s, "dns"))
		return IMITATE_DNS;
	if (!strcmp(s, "stun"))
		return IMITATE_STUN;
	if (!strcmp(s, "sip"))
		return IMITATE_SIP;
	return IMITATE_NONE;
}

const char *imitate_proto_name(enum imitate_proto p)
{
	switch (p) {
	case IMITATE_QUIC: return "quic";
	case IMITATE_DNS:  return "dns";
	case IMITATE_STUN: return "stun";
	case IMITATE_SIP:  return "sip";
	default:           return "none";
	}
}

static u16 clamp_u16(int v)
{
	if (v < 0)
		return 0;
	if (v > 0xFFFF)
		return 0xFFFF;
	return (u16)v;
}

/* EDNS OPT response (RFC 6891). p has length `padding`; `total` is the full
 * datagram length used for RDLENGTH/OPTION-LENGTH. Port of writeDNSOptResponse. */
static void write_dns_opt_response(u8 *p, int total, int padding, const u8 txid[2])
{
	const int opt_off = 12 + 5; /* header + root question = 17 */
	u16 rdlength = clamp_u16(total - (opt_off + 11));      /* total - 28 */
	u16 opt_len = clamp_u16(total - (opt_off + 11 + 4));   /* total - 32 */
	int i;

	p[0] = txid[0]; p[1] = txid[1];
	p[2] = 0x81; p[3] = 0x80;
	p[4] = 0x00; p[5] = 0x01;
	p[6] = 0x00; p[7] = 0x00;
	p[8] = 0x00; p[9] = 0x00;
	p[10] = 0x00; p[11] = 0x01;
	/* root QNAME + QTYPE A + QCLASS IN */
	p[12] = 0x00; p[13] = 0x00; p[14] = 0x01; p[15] = 0x00; p[16] = 0x01;
	/* OPT RR fixed (15 bytes) at opt_off */
	p[opt_off + 0] = 0x00;                 /* root NAME */
	p[opt_off + 1] = 0x00; p[opt_off + 2] = 0x29; /* TYPE OPT */
	p[opt_off + 3] = (u8)(1232 >> 8); p[opt_off + 4] = (u8)(1232 & 0xFF);
	p[opt_off + 5] = 0x00; p[opt_off + 6] = 0x00;
	p[opt_off + 7] = 0x00; p[opt_off + 8] = 0x00;
	p[opt_off + 9] = (u8)(rdlength >> 8); p[opt_off + 10] = (u8)rdlength;
	p[opt_off + 11] = (u8)(0xFDE9 >> 8); p[opt_off + 12] = (u8)(0xFDE9 & 0xFF);
	p[opt_off + 13] = (u8)(opt_len >> 8); p[opt_off + 14] = (u8)opt_len;
	for (i = opt_off + 15; i < padding; i++)
		p[i] = 0x00;
}

/* Legacy TYPE NULL fallback for padding < 32. Port of writeDNSNull. */
static void write_dns_null(u8 *buf, int total, int padding, const u8 txid[2])
{
	u8 qdcount = 0, ancount = 0;
	u16 rdlength;
	u8 fixed[28];
	int advertised, copy_len, i;

	if (padding <= 0)
		return;
	if (padding >= 17)
		qdcount = 1;
	if (padding >= 28)
		ancount = 1;
	rdlength = clamp_u16(total - 28);
	fixed[0] = txid[0]; fixed[1] = txid[1];
	fixed[2] = 0x81; fixed[3] = 0x80;
	fixed[4] = 0x00; fixed[5] = qdcount;
	fixed[6] = 0x00; fixed[7] = ancount;
	fixed[8] = 0x00; fixed[9] = 0x00;
	fixed[10] = 0x00; fixed[11] = 0x00;
	fixed[12] = 0x00;
	fixed[13] = 0x00; fixed[14] = 0x01;
	fixed[15] = 0x00; fixed[16] = 0x01;
	fixed[17] = 0x00;
	fixed[18] = 0x00; fixed[19] = 0x0a;
	fixed[20] = 0x00; fixed[21] = 0x01;
	fixed[22] = 0x00; fixed[23] = 0x00; fixed[24] = 0x00; fixed[25] = 0x3c;
	fixed[26] = (u8)(rdlength >> 8); fixed[27] = (u8)rdlength;

	advertised = 12;
	if (padding >= 28)
		advertised = 28;
	else if (padding >= 17)
		advertised = 17;
	copy_len = padding < advertised ? padding : advertised;
	memcpy(buf, fixed, copy_len);
	for (i = copy_len; i < padding; i++)
		buf[i] = 0x00;
}

static void write_dns_msg(u8 *buf, int total, int padding, const u8 txid[2])
{
	if (padding < 32)
		write_dns_null(buf, total, padding, txid);
	else
		write_dns_opt_response(buf, total, padding, txid);
}

/* QUIC 1-RTT short header (RFC 9000 §17.3.1) + LCG body. Port of
 * obf_imitate.go:writeQUICShort — keep the draw order. */
static void write_quic_short(u8 *buf, int padding, u32 seed)
{
	u32 state = seed;
	u8 spin, key_phase, pn_len_bits;
	int i;

	if (padding <= 0)
		return;
	spin = (u8)(state >> 8) & 0x01; state = lcg_step(state);
	key_phase = (u8)(state >> 8) & 0x01; state = lcg_step(state);
	pn_len_bits = (u8)state & 0x03; state = lcg_step(state);

	buf[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len_bits;
	for (i = 1; i < padding; i++) {
		buf[i] = (u8)(state >> 16); /* middle byte, NOT the low byte */
		state = lcg_step(state);
	}
}

void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto p)
{
	u32 seed;

	if (padding == 0 || padding >= total_len)
		return;
	seed = imitate_fnv1a_seed(buf + padding, total_len - padding);
	switch (p) {
	case IMITATE_QUIC: write_quic_short(buf, padding, seed); break;
	case IMITATE_DNS: {
		u8 txid[2] = { 0, 0 };

		if (total_len - padding > 0) txid[0] = buf[padding];
		if (total_len - padding > 1) txid[1] = buf[padding + 1];
		write_dns_msg(buf, total_len, padding, txid);
		break;
	}
	default: break;
	}
}

void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto p)
{
	if (len <= 0)
		return;
	switch (p) {
	case IMITATE_QUIC: write_quic_short(buf, len, seed); break;
	case IMITATE_DNS: {
		u8 txid[2] = { (u8)(seed >> 8), (u8)seed };

		write_dns_msg(buf, len, len, txid);
		break;
	}
	default: break;
	}
}
