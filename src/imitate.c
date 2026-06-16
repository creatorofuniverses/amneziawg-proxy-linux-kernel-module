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

/* Protocol writers are added in later tasks. */

void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto p)
{
	(void)buf; (void)total_len; (void)padding; (void)p;
}

void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto p)
{
	(void)buf; (void)len; (void)seed; (void)p;
}
