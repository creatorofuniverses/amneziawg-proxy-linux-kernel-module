/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AWG_QINIT_H
#define _AWG_QINIT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include "imitate_shim.h"
#endif

#define QINIT_DATAGRAM_LEN 1200  /* RFC 9000 §14.1 client-Initial minimum */

/* Injectable randomness: production passes a get_random_bytes wrapper; tests
 * pass a deterministic source pinned to a fixed stream. Draw order across the
 * whole build is fixed: dcid(8), scid(8), pn(4), key_share pubkey(32),
 * client_hello random(32).
 */
typedef void (*qinit_rand_fn)(void *rctx, u8 *out, int n);

/* --- primitives (exposed for KATs) --- */
void qinit_hmac_sha256(const u8 *key, u32 klen, const u8 *msg, u32 mlen, u8 out[32]);
void qinit_hkdf_extract(const u8 *salt, u32 slen, const u8 *ikm, u32 ilen, u8 prk[32]);
void qinit_hkdf_expand_label(const u8 *secret, const char *label, u8 *out, u16 len);

#ifdef __KERNEL__
/* get_random_bytes wrapper used by the kernel modifier (Task 11). */
void qinit_rand_getrandom(void *rctx, u8 *out, int n);
#endif

#endif /* _AWG_QINIT_H */
