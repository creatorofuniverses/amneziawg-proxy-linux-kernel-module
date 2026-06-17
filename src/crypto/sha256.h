/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _AWG_CRYPTO_SHA256_H
#define _AWG_CRYPTO_SHA256_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include "imitate_shim.h"
#endif

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN  64

struct sha256_ctx {
	u32 h[8];
	u64 len;
	u8  buf[SHA256_BLOCK_LEN];
	u32 buflen;
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const u8 *data, u32 len);
void sha256_final(struct sha256_ctx *ctx, u8 out[SHA256_DIGEST_LEN]);
void sha256(const u8 *data, u32 len, u8 out[SHA256_DIGEST_LEN]);

#endif /* _AWG_CRYPTO_SHA256_H */
