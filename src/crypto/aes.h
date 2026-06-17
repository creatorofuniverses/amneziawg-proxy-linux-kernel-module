/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AWG_CRYPTO_AES_H
#define _AWG_CRYPTO_AES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include "imitate_shim.h"
#endif

/* AES-128, encrypt-only. qinit has no secret material (keys are public-derivable
 * by RFC 9001 §5.2), so a simple table implementation is safe — no constant-time
 * requirement. The only AES operation qinit needs is single-block encrypt.
 */
struct aes128_ctx {
	u32 rk[44];
};

void aes128_set_encrypt_key(struct aes128_ctx *ctx, const u8 key[16]);
void aes128_encrypt_block(const struct aes128_ctx *ctx, const u8 in[16], u8 out[16]);

#endif /* _AWG_CRYPTO_AES_H */
