/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AWG_IMITATE_H
#define _AWG_IMITATE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include "imitate_shim.h"
#endif

/* Protocol that S-padding / junk / I-packets are shaped to resemble.
 * IMITATE_NONE (zero value) preserves the original get_random_bytes behavior. */
enum imitate_proto {
	IMITATE_NONE = 0,
	IMITATE_QUIC,
	IMITATE_DNS,
	IMITATE_STUN,
	IMITATE_SIP,
};

/* Mechanism A: rewrite buf[0:padding] with filler for p, seeding the PRNG from
 * the real payload at buf[padding:total_len]. No-op if padding == 0 or
 * padding >= total_len. buf[padding:] is never modified. */
void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto p);

/* Mechanisms B/C: write exactly `len` bytes of a fake datagram for p, seeded by
 * the caller-supplied seed (no payload source). */
void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto p);

/* FNV-1a 32-bit over the first <=64 bytes of payload. */
u32 imitate_fnv1a_seed(const u8 *payload, int len);
/* Well-spread LCG seed from a monotonic counter (FNV-1a of its 8 LE bytes). */
u32 imitate_junk_seed(u64 counter);

enum imitate_proto imitate_proto_parse(const char *s);
const char *imitate_proto_name(enum imitate_proto p);

#endif /* _AWG_IMITATE_H */
