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

/* STUN Binding Success Response (RFC 5389). Port of writeSTUN — the LCG draw
 * order (txn x3, then port, addr, then SOFTWARE chars) must not change. */
static void write_stun(u8 *buf, int padding, u32 seed)
{
	u32 state = seed;
	const u32 cookie = 0x2112A442u;
	u8 txn[12];
	u8 header[20];
	int body = 0, written = 0, remaining, i, j, copy_len;

	if (padding <= 0)
		return;
	for (i = 0; i < 12; i += 4)
		put_be32(txn + i, next_lcg(&state));

	if (padding > 20)
		body = (padding - 20) & ~0x3;

	if (body - written >= 12) {
		u16 port = (u16)(next_lcg(&state) >> 16);
		u32 addr = next_lcg(&state);
		u16 xport = port ^ (u16)(cookie >> 16);
		u32 xaddr = addr ^ cookie;
		int off = 20 + written;

		put_be16(buf + off, 0x0020);
		put_be16(buf + off + 2, 8);
		buf[off + 4] = 0x00;
		buf[off + 5] = 0x01;
		put_be16(buf + off + 6, xport);
		put_be32(buf + off + 8, xaddr);
		written += 12;
	}

	remaining = body - written;
	if (remaining >= 4) {
		int vlen = remaining - 4;
		int off = 20 + written;

		if (vlen > 124)
			vlen = 124;
		put_be16(buf + off, 0x8022);
		put_be16(buf + off + 2, (u16)vlen);
		for (j = 0; j < vlen; j++)
			buf[off + 4 + j] = 0x20 + (u8)(next_lcg(&state) % 0x5F);
		written += 4 + vlen;
	}

	put_be16(header, 0x0101);
	put_be16(header + 2, (u16)written);
	put_be32(header + 4, cookie);
	memcpy(header + 8, txn, 12);
	copy_len = padding < 20 ? padding : 20;
	memcpy(buf, header, copy_len);
	for (j = 20 + written; j < padding; j++)
		buf[j] = 0x00;
}

static int decimal_digits(int value)
{
	int digits = 1;

	while (value >= 10) {
		value /= 10;
		digits++;
	}
	return digits;
}

/* Returns the would-be length (full line); copies into p[*pos] iff it + the
 * 2-byte closing blank line still fit. Mirrors Go's putLine. */
static int sip_putline(u8 *p, int *pos, int length, const char *line, int n)
{
	if (*pos + n + 2 <= length) {
		memcpy(p + *pos, line, n);
		*pos += n;
		return 1;
	}
	return 0;
}

/* SIP response header block (RFC 3261). Port of writeSIP. */
static void write_sip(u8 *buf, int total, int padding, u32 seed)
{
	static const char *const status[3] = { "100 Trying", "180 Ringing", "200 OK" };
	static const char *const hosts[3] = { "sip.example.com", "pbx.example.net", "voip.example.org" };
	static const char *const methods[3] = { "INVITE", "OPTIONS", "REGISTER" };
	u32 st = seed;
	int length = padding;
	int status_idx, host_i, method_i, pos = 0, k, all_mandatory;
	u32 branch, from_tag, to_tag, call_id, cseq;
	const char *host, *method;
	char tmp[160];
	int n, i;

	if (padding <= 0)
		return;

	status_idx = (int)(next_lcg(&st) % 3);
	host_i = (int)(next_lcg(&st) % 3);
	method_i = (int)(next_lcg(&st) % 3);
	branch = next_lcg(&st);
	from_tag = next_lcg(&st);
	to_tag = next_lcg(&st);
	call_id = next_lcg(&st);
	cseq = 1 + (st % 100000); /* reads state directly, no further next */
	host = hosts[host_i];
	method = methods[method_i];

	/* Status line: try each rotation until one fits. */
	{
		int status_written = 0;

		for (k = 0; k < 3; k++) {
			const char *s = status[(status_idx + k) % 3];

			n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "SIP/2.0 %s\r\n", s);
			if (sip_putline(buf, &pos, length, tmp, n)) {
				status_written = 1;
				break;
			}
		}
		if (!status_written) {
			static const char frag[] = "SIP/2.0 100 Trying\r\n";
			int take = (int)sizeof(frag) - 1;

			if (take > length)
				take = length;
			memcpy(buf, frag, take);
			for (i = take; i < length; i++)
				buf[i] = ' ';
			if (length >= 2) {
				buf[length - 2] = '\r';
				buf[length - 1] = '\n';
			}
			return;
		}
	}

	n = IMITATE_SNPRINTF(tmp, sizeof(tmp),
		"Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK%08x;rport\r\n", host, branch);
	all_mandatory = sip_putline(buf, &pos, length, tmp, n);
	if (all_mandatory) {
		n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "From: <sip:caller@%s>;tag=%08x\r\n", host, from_tag);
		all_mandatory = sip_putline(buf, &pos, length, tmp, n);
	}
	if (all_mandatory) {
		n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "To: <sip:callee@%s>;tag=%08x\r\n", host, to_tag);
		all_mandatory = sip_putline(buf, &pos, length, tmp, n);
	}
	if (all_mandatory) {
		n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "Call-ID: %08x@%s\r\n", call_id, host);
		all_mandatory = sip_putline(buf, &pos, length, tmp, n);
	}
	if (all_mandatory) {
		n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "CSeq: %u %s\r\n", cseq, method);
		all_mandatory = sip_putline(buf, &pos, length, tmp, n);
	}

	if (all_mandatory) {
		int sws, digits, done = 0;

		for (sws = 1; sws <= 2 && !done; sws++) {
			for (digits = 1; digits <= decimal_digits(total); digits++) {
				int header_end = pos + (int)sizeof("Content-Length:") - 1 +
						 sws + digits + (int)sizeof("\r\n\r\n") - 1;
				if (header_end > length)
					break;
				if (decimal_digits(total - header_end) == digits) {
					int body = total - header_end;

					if (sws == 1)
						n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "Content-Length: %d\r\n", body);
					else
						n = IMITATE_SNPRINTF(tmp, sizeof(tmp), "Content-Length:  %d\r\n", body);
					sip_putline(buf, &pos, length, tmp, n);
					done = 1;
					break;
				}
			}
		}
	}

	if (pos + 2 <= length) {
		buf[pos] = '\r';
		buf[pos + 1] = '\n';
		pos += 2;
	}
	for (i = pos; i < length; i++)
		buf[i] = ' ';
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
	case IMITATE_STUN: write_stun(buf, padding, seed); break;
	case IMITATE_SIP: write_sip(buf, total_len, padding, seed); break;
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
	case IMITATE_STUN: write_stun(buf, len, seed); break;
	case IMITATE_SIP: write_sip(buf, len, len, seed); break;
	default: break;
	}
}

#ifdef __KERNEL__
#include <linux/random.h>
#include "device.h"

void wg_fill_padding(struct wg_device *wg, u8 *buf, int total_len, int padding)
{
	if (wg->imitate_proto != IMITATE_NONE)
		imitate_fill_prefix(buf, total_len, padding, wg->imitate_proto);
	else
		get_random_bytes(buf, padding);
}

void wg_fill_junk(struct wg_device *wg, u8 *buf, int len)
{
	if (wg->imitate_proto != IMITATE_NONE) {
		u32 seed = imitate_junk_seed(atomic64_inc_return(&wg->imitate_junk_counter));

		imitate_fill_whole(buf, len, seed, wg->imitate_proto);
	} else {
		get_random_bytes(buf, len);
	}
}
#endif /* __KERNEL__ */
