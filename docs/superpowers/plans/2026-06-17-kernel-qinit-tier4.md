# Tier 4 `qinit` (fake QUIC Initial + SNI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Tier 4 / `qinit` from the `amneziawg-go-proxy` oracle to the C kernel module — an I-packet decoy that is a complete, header-protected 1200-byte QUIC v1 Initial datagram carrying a TLS 1.3 ClientHello with a benign SNI, structurally byte-identical to the Go oracle.

**Architecture:** New isolated translation unit `src/qinit.c` (+ `src/qinit.h`) holds the QUIC/TLS framing, HKDF, AES-GCM seal, and header protection. Two new vendored primitives — `src/crypto/aes.c` (AES-128 block encrypt) and `src/crypto/sha256.c` — sit under the existing `src/crypto/` umbrella. The builder takes an **injectable randomness function** so the same source is byte-exact-testable against a Go-derived golden vector in userspace and runs with `get_random_bytes` in-kernel. A `void *ctx` field is added to the junk modifier model to carry the per-tag SNI string. No receive-path, netlink/ABI, or `amneziawg-tools-proxy` change.

**Tech Stack:** Out-of-tree Linux kernel C (kernel 3.10–6.x), kbuild, dual-compile via `#ifdef __KERNEL__` + `tests/imitate/imitate_shim.h`, userspace KAT harness (C), Go test refactor (Go 1.24, `crypto/hkdf` stdlib), `make test-qemu`/netns integration.

## Global Constraints

Copied verbatim from the spec (`docs/superpowers/specs/2026-06-17-kernel-qinit-tier4-design.md`). Every task's requirements implicitly include these:

- **Linux kernel coding style** (tabs, SPDX `// SPDX-License-Identifier: GPL-2.0` / `/* ... */` headers). `make style` (checkpatch `--max-line-length=4000 --codespell`) **must pass before every C commit.**
- **Dual-compile.** `src/qinit.c`, `src/crypto/aes.c`, `src/crypto/sha256.c` and their headers MUST compile both in-kernel and in the userspace harness. Follow the existing `src/imitate.c` pattern: `#ifdef __KERNEL__` → `<linux/string.h>`; `#else` → `<string.h>`. Use the `u8/u16/u32/u64` types from `<linux/types.h>` (kernel) / `imitate_shim.h` (userspace). **Hand-roll all big-endian byte I/O** (`put_be16`/`put_be32` style, as `imitate.c` already does) — do NOT use `htons`/`cpu_to_be*`, which diverge across kernel/userspace.
- **No `CONFIG_CRYPTO_*` dependency.** All crypto is vendored software primitives. No kernel crypto API, no `tfm` lifetimes, no allocations in the builder.
- **No heap allocation in `qinit_build`.** Caller provides the output buffer; the builder uses only fixed-size stack scratch. Respect the `-Wframe-larger-than=2048` budget in `src/Kbuild` — keep per-function stack scratch small.
- **No ABI change.** The `WGDEVICE_A_IMITATE_PROTOCOL` enum and all netlink ordinals stay frozen. `qinit` rides opaque in the existing `I1`–`I5` desc strings.
- **No `amneziawg-tools-proxy` change.** The only non-kernel repo touched is `amneziawg-go-proxy`, and only for behavior-preserving test infrastructure.
- **`QINIT_DATAGRAM_LEN` = 1200** (RFC 9000 §14.1 client-Initial minimum). Must satisfy the existing `pkt_size > MESSAGE_MAX_SIZE` (65535) guard in `jp_spec_setup` — 1200 passes trivially.
- **Random draw order is load-bearing:** `dcid (8), scid (8), pn (4), key_share pubkey (32), client_hello random (32)` — total 84 bytes, drawn in exactly this order by both C and Go so a pinned stream reproduces the oracle's structure byte-for-byte.
- **HKDF-Extract argument order is load-bearing:** `initial_secret = HMAC-SHA256(key = quic_v1_initial_salt, msg = dcid)`. Salt is the HMAC **key**, DCID is the IKM. (RFC 9001 A.1 vector only passes if correct — see Task 7.)
- **`ctx` is the highest-risk change** (UAF-sensitive junk path). Copy semantics, symmetric teardown, no shared pointer across the tag/mod boundary (Task 10). KASAN/ASan-gate it.

### Convention for standardized primitives (AES-128, SHA-256, HMAC, HKDF, GHASH/GCM)

These are closed, standardized algorithms with published byte-exact known-answer tests. For each, this plan gives the **exact public API**, the **exact KAT vectors**, and the **authoritative standard reference**. The implementer writes the standard algorithm; **the KAT is the acceptance gate** — a passing KAT against the published vector IS proof of correctness. This is deliberate: transcribing a 256-entry S-box or 64-entry round-constant table into a plan and trusting it verbatim is more error-prone than implementing from the normative FIPS/RFC text against an exact test. Project-specific logic (the QUIC/TLS port, `junk.c` surgery, build wiring, Go refactor, harness) is given as complete literal code, with no such latitude.

---

## File Structure

**New files (kernel repo):**

- `src/crypto/aes.h` / `src/crypto/aes.c` — AES-128 key expansion + single-block encrypt. The only AES op qinit needs (used by GCM keystream/GHASH `H = E(0)` and by ECB header-protection masking). No decrypt.
- `src/crypto/sha256.h` / `src/crypto/sha256.c` — SHA-256 one-shot + incremental.
- `src/qinit.h` / `src/qinit.c` — HMAC-SHA256, HKDF-Extract/Expand-Label, `derive_initial_keys`, AES-128-GCM seal, QUIC varint, TLS 1.3 ClientHello, CRYPTO frame, header protection, and the public `qinit_build` builder. Mirrors `device/obf_imitate_quic.go` structure-for-structure.
- `src/selftest/qinit.c` — in-kernel KATs (primitives + RFC 9001 A.1 + golden vector), `#include`d into the debug build, called from `main.c` (mirrors `selftest/counter.c` pattern).
- `tests/imitate/qinit_kat.c` — userspace KAT + golden-vector + round-trip + property test harness.
- `tests/imitate/testdata/qinit_vector.bin` — committed Go-derived golden datagram (Task 6).
- `tests/imitate/testdata/qinit_rand.bin` — the committed 84-byte pinned random stream (Task 6).

**Modified files (kernel repo):**

- `src/junk.h` — `jp_modifier_func` gains `void *ctx`; `jp_tag` and `jp_modifier` gain a `ctx` field.
- `src/junk.c` — `void *ctx` added to all 9 existing modifiers; `qinit` keyword + `parse_qinit_tag` + `qinit_modifier`; `ctx` copy in `jp_spec_setup`; `ctx` free in `jp_tag_free`/`jp_spec_free`; qinit-exclusivity validation.
- `src/Kbuild` — add `qinit.o`, `crypto/aes.o`, `crypto/sha256.o` to `amneziawg-y`.
- `src/main.c` — call the qinit selftest under `CONFIG_AMNEZIAWG_DEBUG`.
- `tests/imitate/Makefile` — build + run the `qinit_kat` target.
- `src/tests/imitate-netns.sh` — add an `i1=<qinit example.com>` end-to-end case.

**Modified files (Go repo `amneziawg-go-proxy`, test-only / behavior-preserving):**

- `device/obf_imitate_quic.go` — `buildQUICInitial`/`buildClientHello` gain an `io.Reader`; existing entry points become thin wrappers passing `crypto/rand.Reader`.
- `device/obf_imitate_quic_test.go` — pinned-stream deterministic build → regenerate/assert the committed golden vector (drift guard).

**Tools repo (`amneziawg-tools-proxy`):** untouched.

---

## Phase 1 — Vendored primitives + Layer-1 KATs (userspace, no kernel behavior change)

### Task 1: AES-128 block encrypt (`src/crypto/aes.c` + KAT)

**Files:**
- Create: `src/crypto/aes.h`, `src/crypto/aes.c`
- Create: `tests/imitate/qinit_kat.c` (KAT harness — grown across Tasks 1–4, 7–9, 12)
- Modify: `tests/imitate/Makefile`

**Interfaces:**
- Produces:
  ```c
  struct aes128_ctx { u32 rk[44]; };               /* 11 round keys × 4 words */
  void aes128_set_encrypt_key(struct aes128_ctx *c, const u8 key[16]);
  void aes128_encrypt_block(const struct aes128_ctx *c, const u8 in[16], u8 out[16]);
  ```

- [ ] **Step 1: Write `src/crypto/aes.h`**

```c
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
 * requirement. The only AES operation qinit needs is single-block encrypt. */
struct aes128_ctx {
	u32 rk[44];
};

void aes128_set_encrypt_key(struct aes128_ctx *ctx, const u8 key[16]);
void aes128_encrypt_block(const struct aes128_ctx *ctx, const u8 in[16], u8 out[16]);

#endif /* _AWG_CRYPTO_AES_H */
```

- [ ] **Step 2: Write the failing KAT into `tests/imitate/qinit_kat.c`**

Create the harness skeleton with the FIPS-197 Appendix C.1 known-answer vector:

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include "imitate_shim.h"
#include "../../src/crypto/aes.h"

static int fails;

static int eq(const char *name, const u8 *got, const u8 *want, int n)
{
	if (memcmp(got, want, n) == 0) { printf("PASS %s\n", name); return 1; }
	printf("FAIL %s\n", name);
	fails++;
	return 0;
}

/* FIPS-197 Appendix B / C.1: AES-128 single block. */
static void test_aes128_fips197(void)
{
	const u8 key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	const u8 pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
			    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	const u8 ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
			    0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
	struct aes128_ctx c;
	u8 out[16];

	aes128_set_encrypt_key(&c, key);
	aes128_encrypt_block(&c, pt, out);
	eq("aes128_fips197", out, ct, 16);
}

int main(void)
{
	test_aes128_fips197();
	printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
	return fails ? 1 : 0;
}
```

- [ ] **Step 3: Wire the harness into `tests/imitate/Makefile`**

Add below the existing `harness:` rule:

```make
QINIT_SRC := ../../src/crypto/aes.c ../../src/crypto/sha256.c ../../src/qinit.c
qinit_kat: qinit_kat.c $(QINIT_SRC)
	$(CC) $(CFLAGS) -o qinit_kat qinit_kat.c $(QINIT_SRC)

test-qinit: qinit_kat
	./qinit_kat
```

Add `qinit_kat` to the `clean:` rule's `rm -f`. (sha256.c/qinit.c don't exist yet — for Task 1 only, temporarily build with just `aes.c`; revert `QINIT_SRC` to the full list once Task 3 lands. Note this in the commit.)

- [ ] **Step 4: Run the KAT to verify it fails to build/link**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to aes128_set_encrypt_key`.

- [ ] **Step 5: Implement `src/crypto/aes.c`**

Implement AES-128 key expansion + single-block encrypt per **FIPS-197**:
- Use the standard FIPS-197 forward S-box (Figure 7) and the AES-128 round constants `Rcon = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}`.
- `aes128_set_encrypt_key`: expand the 16-byte key to 44 words (`Nk=4, Nr=10`) using `RotWord`/`SubWord`/`Rcon` (FIPS-197 §5.2).
- `aes128_encrypt_block`: `AddRoundKey`, 9× (`SubBytes`,`ShiftRows`,`MixColumns`,`AddRoundKey`), final round without `MixColumns` (FIPS-197 §5.1). A T-table or byte-wise implementation is fine; no constant-time requirement.
- Includes: `#ifdef __KERNEL__ #include <linux/string.h> #else #include <string.h> #endif`, then `#include "aes.h"`. Hand-roll any big-endian word packing.

The KAT in Step 2 is the acceptance gate.

- [ ] **Step 6: Run the KAT to verify it passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS aes128_fips197` and `ALL PASS`.

- [ ] **Step 7: Commit**

```bash
git add src/crypto/aes.h src/crypto/aes.c tests/imitate/qinit_kat.c tests/imitate/Makefile
git commit -m "feat(qinit): vendored AES-128 block encrypt + FIPS-197 KAT"
```

---

### Task 2: SHA-256 (`src/crypto/sha256.c` + KAT)

**Files:**
- Create: `src/crypto/sha256.h`, `src/crypto/sha256.c`
- Modify: `tests/imitate/qinit_kat.c`

**Interfaces:**
- Produces:
  ```c
  struct sha256_ctx { u32 h[8]; u64 len; u8 buf[64]; u32 buflen; };
  void sha256_init(struct sha256_ctx *c);
  void sha256_update(struct sha256_ctx *c, const u8 *data, u32 len);
  void sha256_final(struct sha256_ctx *c, u8 out[32]);
  void sha256(const u8 *data, u32 len, u8 out[32]);   /* one-shot convenience */
  ```

- [ ] **Step 1: Write `src/crypto/sha256.h`**

```c
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
```

- [ ] **Step 2: Add the failing SHA-256 KATs to `qinit_kat.c`**

Add `#include "../../src/crypto/sha256.h"` and these tests (call both from `main`):

```c
/* FIPS-180-4 / NIST CAVP. */
static void test_sha256(void)
{
	u8 out[32];
	/* "abc" */
	const u8 want_abc[32] = {
		0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
		0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
	/* "" (empty) */
	const u8 want_empty[32] = {
		0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
		0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};

	sha256((const u8 *)"abc", 3, out);
	eq("sha256_abc", out, want_abc, 32);
	sha256((const u8 *)"", 0, out);
	eq("sha256_empty", out, want_empty, 32);
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to sha256`.

- [ ] **Step 4: Implement `src/crypto/sha256.c`**

Implement SHA-256 per **FIPS-180-4**: the 8 initial hash values `0x6a09e667…0x5be0cd19`, the 64 round constants `K[0..63]` (FIPS-180-4 §4.2.2), big-endian message-length padding, and the compression function (`Ch`, `Maj`, `Σ0/Σ1`, `σ0/σ1`, `rotr`). Provide `sha256_init/update/final` plus a one-shot `sha256()`. Big-endian length and digest output must be hand-rolled. The KATs are the gate.

- [ ] **Step 5: Run to verify it passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS sha256_abc`, `PASS sha256_empty`.

- [ ] **Step 6: Commit**

```bash
git add src/crypto/sha256.h src/crypto/sha256.c tests/imitate/qinit_kat.c
git commit -m "feat(qinit): vendored SHA-256 + FIPS-180-4 KAT"
```

---

### Task 3: HMAC-SHA256 + HKDF (in `src/qinit.c` + KATs)

**Files:**
- Create: `src/qinit.h`, `src/qinit.c`
- Modify: `tests/imitate/qinit_kat.c`, `tests/imitate/Makefile` (restore full `QINIT_SRC`)

**Interfaces:**
- Consumes: `sha256_*` (Task 2).
- Produces (non-static so KATs can call them directly):
  ```c
  void qinit_hmac_sha256(const u8 *key, u32 klen, const u8 *msg, u32 mlen, u8 out[32]);
  void qinit_hkdf_extract(const u8 *salt, u32 slen, const u8 *ikm, u32 ilen, u8 prk[32]);
  /* TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1): "tls13 " prefix, zero-length context. */
  void qinit_hkdf_expand_label(const u8 *secret, const char *label, u8 *out, u16 len);
  ```

- [ ] **Step 1: Write `src/qinit.h` (initial)**

```c
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
 * client_hello random(32). */
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
```

- [ ] **Step 2: Add the failing HMAC + HKDF KATs to `qinit_kat.c`**

Add `#include "../../src/qinit.h"` and (call from `main`):

```c
/* RFC 4231 test case 1. */
static void test_hmac_sha256(void)
{
	u8 key[20], out[32];
	const u8 want[32] = {
		0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
		0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};
	memset(key, 0x0b, sizeof(key));
	qinit_hmac_sha256(key, sizeof(key), (const u8 *)"Hi There", 8, out);
	eq("hmac_sha256_rfc4231_1", out, want, 32);
}

/* RFC 5869 Appendix A.1 (SHA-256): Extract then Expand. Expand here uses the raw
 * RFC info, so test it via qinit_hkdf_extract + a direct expand check below. */
static void test_hkdf_extract(void)
{
	const u8 ikm[22] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
			    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
	const u8 salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
	const u8 want_prk[32] = {
		0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
		0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5};
	u8 prk[32];
	qinit_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
	eq("hkdf_extract_rfc5869", prk, want_prk, 32);
}
```

(The end-to-end HKDF-Expand-Label correctness is proven byte-exactly by the RFC 9001 A.1 key-schedule KAT in Task 7, which exercises `qinit_hkdf_expand_label` with the `"tls13 "` prefix and real labels.)

- [ ] **Step 3: Restore the full harness source list in `tests/imitate/Makefile`**

Set `QINIT_SRC := ../../src/crypto/aes.c ../../src/crypto/sha256.c ../../src/qinit.c` (now that all three exist).

- [ ] **Step 4: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to qinit_hmac_sha256`.

- [ ] **Step 5: Implement `src/qinit.c` (HMAC + HKDF only, for now)**

```c
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
 * suffices — assert and handle exactly that. */
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
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS hmac_sha256_rfc4231_1`, `PASS hkdf_extract_rfc5869`.

- [ ] **Step 7: Run style check**

Run: `cd src && make style` (expect clean on the new files).

- [ ] **Step 8: Commit**

```bash
git add src/qinit.h src/qinit.c tests/imitate/qinit_kat.c tests/imitate/Makefile
git commit -m "feat(qinit): HMAC-SHA256 + HKDF (extract/expand-label) + RFC KATs"
```

---

### Task 4: AES-128-GCM seal (in `src/qinit.c` + NIST KAT)

**Files:**
- Modify: `src/qinit.h`, `src/qinit.c`
- Modify: `tests/imitate/qinit_kat.c`

**Interfaces:**
- Consumes: `aes128_*` (Task 1).
- Produces:
  ```c
  /* AES-128-GCM AEAD seal, 96-bit nonce, 16-byte tag appended after ciphertext.
   * out must hold ptlen + 16 bytes. */
  void qinit_aes128_gcm_seal(const u8 key[16], const u8 nonce[12],
                             const u8 *aad, u32 aadlen,
                             const u8 *pt, u32 ptlen, u8 *out);
  ```

- [ ] **Step 1: Declare `qinit_aes128_gcm_seal` in `src/qinit.h`**

Add the prototype under the primitives section.

- [ ] **Step 2: Add the failing GCM KAT to `qinit_kat.c`**

Use **McGrew & Viega GCM spec Test Case 4** (AES-128, 96-bit IV, with AAD — exercises GHASH over AAD + ciphertext, the qinit path). Inputs are given; assert the harness output equals the published `ciphertext || tag`:

```c
/* GCM spec (McGrew & Viega) Test Case 4: AES-128, 96-bit IV, AAD present. */
static void test_aes128_gcm(void)
{
	const u8 key[16]   = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
			      0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
	const u8 nonce[12] = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
	const u8 aad[20]   = {0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,
			      0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2};
	const u8 pt[60] = {
		0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
		0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
		0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
		0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39};
	/* Expected ciphertext (60) then tag (16) — GCM spec Test Case 4. */
	const u8 want[76] = {
		0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
		0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
		0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
		0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,
		0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47};
	u8 out[76];

	qinit_aes128_gcm_seal(key, nonce, aad, sizeof(aad), pt, sizeof(pt), out);
	eq("aes128_gcm_tc4", out, want, sizeof(want));
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to qinit_aes128_gcm_seal`.

- [ ] **Step 4: Implement `qinit_aes128_gcm_seal` in `src/qinit.c`**

Implement standard AES-128-GCM (NIST SP 800-38D), built on `aes128_encrypt_block`:
- `H = AES_K(0^128)`.
- CTR keystream from `J0 = nonce || 0x00000001` (96-bit nonce path), encrypting counter blocks starting at `J0+1` to produce ciphertext = `pt XOR keystream`.
- GHASH over `AAD || pad || CT || pad || (len(AAD)||len(CT) in bits, 64-bit each)`, with the standard GF(2^128) multiply (bit `0x80>>...` reflected; reduction polynomial `0xe1`-prefixed). Hand-roll the multiply byte-wise — no secret material, no constant-time need.
- `tag = GHASH_result XOR AES_K(J0)`; append after ciphertext.

The NIST Test Case 4 KAT is the gate. Keep stack scratch small (a few 16-byte blocks) for the kernel `-Wframe-larger-than=2048` budget.

- [ ] **Step 5: Run to verify it passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS aes128_gcm_tc4`.

- [ ] **Step 6: Style + commit**

```bash
cd src && make style && cd ..
git add src/qinit.h src/qinit.c tests/imitate/qinit_kat.c
git commit -m "feat(qinit): AES-128-GCM seal + NIST GCM KAT"
```

---

## Phase 2 — Go oracle randomness refactor + committed golden vector

> Repo: `amneziawg-go-proxy` (sibling checkout at `../amneziawg-go-proxy`, confirmed present). Behavior-preserving: production output stays byte-for-byte identical because the wrappers pass `crypto/rand.Reader` in the same draw order.

### Task 5: Inject `io.Reader` randomness into the Go builders (behavior-preserving)

**Files (in `../amneziawg-go-proxy`):**
- Modify: `device/obf_imitate_quic.go`
- Test: `device/obf_imitate_quic_test.go` (existing tests must still pass)

**Interfaces:**
- Produces:
  ```go
  func buildClientHelloWithRand(r io.Reader, sni string, scid []byte) []byte
  func buildQUICInitialWithRand(r io.Reader, sni string, datagramLen int) []byte
  // existing entry points unchanged in signature:
  func buildClientHello(sni string, scid []byte) []byte      // wrapper → rand.Reader
  func buildQUICInitial(sni string, datagramLen int) []byte  // wrapper → rand.Reader
  ```

- [ ] **Step 1: Verify the existing Go tests are green (baseline)**

Run: `cd ../amneziawg-go-proxy && go test ./device/ -run 'QInit|QUIC|ClientHello|InitialKeys|Varint' -v`
Expected: PASS (records the behavior we must preserve).

- [ ] **Step 2: Refactor `buildClientHello` to take an `io.Reader`**

In `device/obf_imitate_quic.go`, add `"io"` to imports. Rename the body to `buildClientHelloWithRand(r io.Reader, sni string, scid []byte) []byte`, replacing the two `rand.Read(pub)` / `rand.Read(random)` calls with `io.ReadFull(r, pub)` / `io.ReadFull(r, random)` (panic on error — inputs are fixed-size). Add the wrapper:

```go
func buildClientHello(sni string, scid []byte) []byte {
	return buildClientHelloWithRand(rand.Reader, sni, scid)
}
```

- [ ] **Step 3: Refactor `buildQUICInitial` to take an `io.Reader`**

Rename the body to `buildQUICInitialWithRand(r io.Reader, sni string, datagramLen int) []byte`. Replace the three `rand.Read(dcid/scid/pn)` with `io.ReadFull(r, ...)`, and the internal `buildClientHello(sni, scid)` call with `buildClientHelloWithRand(r, sni, scid)` — preserving the draw order `dcid, scid, pn, key_share pub, ch random`. Add the wrapper:

```go
func buildQUICInitial(sni string, datagramLen int) []byte {
	return buildQUICInitialWithRand(rand.Reader, sni, datagramLen)
}
```

- [ ] **Step 4: Run the existing tests to verify behavior is preserved**

Run: `cd ../amneziawg-go-proxy && go test ./device/ -run 'QInit|QUIC|ClientHello|InitialKeys|Varint' -v`
Expected: PASS (same as Step 1 — wrappers reproduce prior behavior).

- [ ] **Step 5: Commit (in the Go repo)**

```bash
cd ../amneziawg-go-proxy
git add device/obf_imitate_quic.go
git commit -m "test(imitate): inject io.Reader randomness into QUIC Initial builders"
cd -
```

---

### Task 6: Pin a fixed stream, generate + commit the golden vector, add Go drift guard

**Files (in `../amneziawg-go-proxy`):**
- Modify: `device/obf_imitate_quic_test.go`
- Create (committed into the **kernel** repo): `tests/imitate/testdata/qinit_rand.bin`, `tests/imitate/testdata/qinit_vector.bin`

**Interfaces:**
- Consumes: `buildQUICInitialWithRand` (Task 5).
- Produces: the 84-byte pinned random stream and the 1200-byte golden datagram, both committed in the kernel repo for the C byte-exact test (Task 9).

The pinned stream is fixed and human-auditable: 84 bytes = `dcid(8)=00..07`, `scid(8)=10..17`, `pn(4)=20 21 22 23`, `key_share(32)=30..4f`, `ch_random(32)=50..6f`.

- [ ] **Step 1: Add a Go test that builds from the pinned stream and writes the vector**

In `device/obf_imitate_quic_test.go`:

```go
// qinitPinnedStream is the fixed 84-byte randomness used to make qinit
// deterministic for the cross-impl golden vector. Draw order:
// dcid(8), scid(8), pn(4), key_share pub(32), client_hello random(32).
func qinitPinnedStream() []byte {
	s := make([]byte, 84)
	for i := 0; i < 8; i++ {
		s[i] = byte(i)        // dcid 00..07
		s[8+i] = byte(0x10 + i) // scid 10..17
	}
	s[16], s[17], s[18], s[19] = 0x20, 0x21, 0x22, 0x23 // pn
	for i := 0; i < 32; i++ {
		s[20+i] = byte(0x30 + i) // key_share 30..4f
		s[52+i] = byte(0x50 + i) // ch random 50..6f
	}
	return s
}

// Regenerate the committed golden vector with WRITE_QINIT_VECTOR=1:
//   WRITE_QINIT_VECTOR=<path> go test ./device/ -run TestQInitGoldenVector
func TestQInitGoldenVector(t *testing.T) {
	got := buildQUICInitialWithRand(bytes.NewReader(qinitPinnedStream()), "example.com", 1200)
	if len(got) != 1200 {
		t.Fatalf("len = %d, want 1200", len(got))
	}
	if p := os.Getenv("WRITE_QINIT_VECTOR"); p != "" {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d bytes to %s", len(got), p)
		return
	}
	// Drift guard: compare against the committed vector in the kernel repo.
	want, err := os.ReadFile("../../amneziawg-proxy-linux-kernel-module/tests/imitate/testdata/qinit_vector.bin")
	if err != nil {
		t.Skipf("golden vector not found (run with WRITE_QINIT_VECTOR): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("datagram drifted from committed golden vector")
	}
}
```

Add `"os"` to the test imports.

- [ ] **Step 2: Generate and commit the pinned stream + golden vector into the kernel repo**

```bash
cd /home/kowalski/projects/vpn/amneziawg-proxy-linux-kernel-module
mkdir -p tests/imitate/testdata
# Write the 84-byte pinned stream (matches qinitPinnedStream()).
python3 -c "import sys; b=bytes(range(8))+bytes(range(0x10,0x18))+bytes([0x20,0x21,0x22,0x23])+bytes(range(0x30,0x50))+bytes(range(0x50,0x70)); open('tests/imitate/testdata/qinit_rand.bin','wb').write(b); assert len(b)==84"
# Generate the golden datagram from Go.
cd ../amneziawg-go-proxy
WRITE_QINIT_VECTOR="$(pwd)/../amneziawg-proxy-linux-kernel-module/tests/imitate/testdata/qinit_vector.bin" \
  go test ./device/ -run TestQInitGoldenVector -v
cd -
```

- [ ] **Step 3: Verify the Go drift guard now passes against the committed vector**

Run: `cd ../amneziawg-go-proxy && go test ./device/ -run TestQInitGoldenVector -v`
Expected: PASS (no `WRITE_QINIT_VECTOR` → compares against committed file).

- [ ] **Step 4: Sanity-check the committed artifacts**

Run: `wc -c tests/imitate/testdata/qinit_vector.bin tests/imitate/testdata/qinit_rand.bin`
Expected: `1200` and `84` bytes respectively.

- [ ] **Step 5: Commit (Go test in Go repo; binaries in kernel repo)**

```bash
cd ../amneziawg-go-proxy
git add device/obf_imitate_quic_test.go
git commit -m "test(imitate): pinned-stream qinit golden vector + drift guard"
cd -
git add tests/imitate/testdata/qinit_vector.bin tests/imitate/testdata/qinit_rand.bin
git commit -m "test(qinit): commit Go-derived golden vector + pinned random stream"
```

---

## Phase 3 — `qinit.c` builder + Layer-2 byte-exact correctness

### Task 7: `derive_initial_keys` + RFC 9001 A.1 key-schedule byte-exact KAT

**Files:**
- Modify: `src/qinit.h`, `src/qinit.c`, `tests/imitate/qinit_kat.c`

**Interfaces:**
- Consumes: `qinit_hkdf_extract`, `qinit_hkdf_expand_label`.
- Produces:
  ```c
  void qinit_derive_initial_keys(const u8 *dcid, u32 dcidlen,
                                 u8 key[16], u8 iv[12], u8 hp[16]);
  ```

- [ ] **Step 1: Declare `qinit_derive_initial_keys` in `src/qinit.h`**

- [ ] **Step 2: Add the failing RFC 9001 A.1 KAT to `qinit_kat.c`**

```c
/* RFC 9001 Appendix A.1: client Initial keys for DCID 0x8394c8f03e515708. */
static void test_derive_initial_keys_rfc9001(void)
{
	const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
	const u8 wk[16] = {0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,
			   0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d};
	const u8 wiv[12] = {0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,0x46,0xfb,0x25,0x5c};
	const u8 whp[16] = {0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,
			    0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2};
	u8 key[16], iv[12], hp[16];

	qinit_derive_initial_keys(dcid, sizeof(dcid), key, iv, hp);
	eq("rfc9001_key", key, wk, 16);
	eq("rfc9001_iv", iv, wiv, 12);
	eq("rfc9001_hp", hp, whp, 16);
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to qinit_derive_initial_keys`.

- [ ] **Step 4: Implement `qinit_derive_initial_keys` in `src/qinit.c`**

```c
/* RFC 9001 §5.2 client Initial key derivation. The salt is the HMAC *key* and
 * the DCID is the IKM (initial_secret = HMAC(key=salt, msg=dcid)) — the order is
 * load-bearing; the A.1 KAT only passes if it is correct. */
static const u8 quic_v1_initial_salt[20] = {
	0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
	0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a,
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
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS rfc9001_key`, `PASS rfc9001_iv`, `PASS rfc9001_hp`. This transitively proves SHA-256 → HMAC → HKDF-Extract/Expand-Label end-to-end.

- [ ] **Step 6: Style + commit**

```bash
cd src && make style && cd ..
git add src/qinit.h src/qinit.c tests/imitate/qinit_kat.c
git commit -m "feat(qinit): RFC 9001 Initial key derivation + A.1 byte-exact KAT"
```

---

### Task 8: QUIC varint + TLS 1.3 ClientHello + CRYPTO frame builders

**Files:**
- Modify: `src/qinit.c`, `tests/imitate/qinit_kat.c`

These are direct ports of `device/obf_imitate_quic.go`. All `static` (internal to `qinit.c`); tested via `qinit_build` in Task 9 and one targeted varint KAT here. The randomness needed (key_share pubkey, ClientHello random) is drawn from a `qinit_rand_fn` passed through, preserving the global draw order.

**Interfaces (internal to `qinit.c`):**
- Produces (static):
  ```c
  static u8 *qinit_put_varint(u8 *p, u64 v);
  static int qinit_build_client_hello(u8 *out, const char *sni,
                                       const u8 *scid, u32 scidlen,
                                       qinit_rand_fn rand, void *rctx);
  static int qinit_build_crypto_frame(u8 *out, const u8 *ch, int chlen);
  ```

- [ ] **Step 1: Add a failing QUIC varint KAT to `qinit_kat.c`**

Expose a thin test shim. Add to `src/qinit.h` under `#ifndef __KERNEL__` (test-only):

```c
#ifndef __KERNEL__
int qinit_test_put_varint(u8 *out, u64 v);  /* returns bytes written */
#endif
```

KAT (mirrors the Go `TestAppendQUICVarint` cases):

```c
static void test_varint(void)
{
	struct { u64 v; const char *hex; int n; } cs[] = {
		{0, "00", 1}, {63, "3f", 1}, {1174, "4496", 2},
		{494878333, "9d7f3e7d", 4},
	};
	u8 out[8];
	char hx[20];
	unsigned i, j;
	int n;

	for (i = 0; i < sizeof(cs)/sizeof(cs[0]); i++) {
		n = qinit_test_put_varint(out, cs[i].v);
		hx[0] = 0;
		for (j = 0; j < (unsigned)n; j++)
			sprintf(hx + 2*j, "%02x", out[j]);
		if (n == cs[i].n && !strcmp(hx, cs[i].hex)) {
			printf("PASS varint_%llu\n", (unsigned long long)cs[i].v);
		} else {
			printf("FAIL varint_%llu got %s\n", (unsigned long long)cs[i].v, hx);
			fails++;
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to qinit_test_put_varint`.

- [ ] **Step 3: Implement the varint, ClientHello, and CRYPTO-frame builders in `src/qinit.c`**

Port from `device/obf_imitate_quic.go` (`appendQUICVarint`, `buildClientHello`, `buildCryptoFrame`, plus the `appendU8Vec`/`appendU16Vec`/`tlsExtension` helpers). Write into caller buffers (no allocation). Big-endian via hand-rolled helpers. Key points to preserve byte-for-byte:
- Extension order: `server_name(0x0000)`, `supported_versions(0x002b)=[0x0304]`, `supported_groups(0x000a)=[0x001d]`, `key_share(0x0033)` x25519 + 32 random bytes, `signature_algorithms(0x000d)=[0x0403,0x0804,0x0401]`, `alpn(0x0010)=["h3"]`, `quic_transport_parameters(0x0039)` with `initial_source_connection_id(0x0f) = scid`.
- ClientHello body: `legacy_version 0x0303`, 32 random bytes, empty `legacy_session_id`, `cipher_suites [0x1301,0x1302,0x1303]`, `compression [0x00]`, then `extensions`.
- Handshake wrapper: `0x01` + u24 length + body.
- **Draw order inside ClientHello: key_share pubkey (32) BEFORE the ClientHello random (32)** — matches the Go body order (`rand.Read(pub)` at the key_share extension, then `rand.Read(random)` for the body). Drawing both up front is fine as long as pub is drawn first.
- CRYPTO frame: `appendQUICVarint(0x06)` (type) + varint offset `0` + varint length + data.

Add the test shim at the bottom of `qinit.c`:

```c
#ifndef __KERNEL__
int qinit_test_put_varint(u8 *out, u64 v)
{
	return (int)(qinit_put_varint(out, v) - out);
}
#endif
```

- [ ] **Step 4: Run to verify the varint KAT passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS varint_0`, `PASS varint_63`, `PASS varint_1174`, `PASS varint_494878333`.

- [ ] **Step 5: Style + commit**

```bash
cd src && make style && cd ..
git add src/qinit.h src/qinit.c tests/imitate/qinit_kat.c
git commit -m "feat(qinit): QUIC varint + TLS 1.3 ClientHello + CRYPTO frame builders"
```

---

### Task 9: `qinit_build` datagram assembly + header protection — golden vector + round-trip

**Files:**
- Modify: `src/qinit.h`, `src/qinit.c`, `tests/imitate/qinit_kat.c`

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces:
  ```c
  /* Build a QINIT_DATAGRAM_LEN-byte QUIC v1 Initial carrying a ClientHello with
   * `sni` into buf (>= QINIT_DATAGRAM_LEN). Returns 0 or -errno. */
  int qinit_build(u8 *buf, const char *sni, qinit_rand_fn rand, void *rctx);
  ```

- [ ] **Step 1: Declare `qinit_build` in `src/qinit.h`** (public — used by the kernel modifier in Task 11).

- [ ] **Step 2: Add the failing golden-vector + round-trip tests to `qinit_kat.c`**

The deterministic source replays the committed `qinit_rand.bin`; the golden test asserts byte-equality with `qinit_vector.bin` (true C↔Go cross-impl proof). The round-trip test re-derives keys, strips header protection, AEAD-opens, and finds the SNI (semantic validity).

```c
#include <stdio.h>
/* Deterministic rand source: sequential replay of a fixed buffer. */
struct fixedrand { const u8 *p; int n, off; };
static void fixedrand_fn(void *rctx, u8 *out, int n)
{
	struct fixedrand *fr = rctx;
	int i;
	for (i = 0; i < n; i++)
		out[i] = (fr->off < fr->n) ? fr->p[fr->off++] : 0;
}

static int read_file(const char *path, u8 *buf, int max)
{
	FILE *f = fopen(path, "rb");
	int n;
	if (!f) return -1;
	n = (int)fread(buf, 1, max, f);
	fclose(f);
	return n;
}

static void test_golden_vector(void)
{
	u8 stream[84], want[1200], got[1200];
	struct fixedrand fr;
	if (read_file("testdata/qinit_rand.bin", stream, sizeof(stream)) != 84 ||
	    read_file("testdata/qinit_vector.bin", want, sizeof(want)) != 1200) {
		printf("FAIL golden_vector (testdata missing)\n"); fails++; return;
	}
	fr.p = stream; fr.n = 84; fr.off = 0;
	if (qinit_build(got, "example.com", fixedrand_fn, &fr) != 0) {
		printf("FAIL golden_vector (build err)\n"); fails++; return;
	}
	eq("golden_vector", got, want, 1200);
}
```

For the round-trip test, add a small decoder in the harness (test-only, NOT in `qinit.c`): re-derive keys from the DCID in the header, AES-ECB the HP sample to unmask `byte0` + PN, build the nonce, AEAD-open (an `aes128_gcm_open` test helper local to the harness), then scan the recovered plaintext for the SNI bytes `"example.com"` and assert presence:

```c
static void test_round_trip(void)
{
	u8 stream[84], pkt[1200];
	struct fixedrand fr;
	if (read_file("testdata/qinit_rand.bin", stream, sizeof(stream)) != 84) {
		printf("FAIL round_trip (testdata missing)\n"); fails++; return;
	}
	fr.p = stream; fr.n = 84; fr.off = 0;
	qinit_build(pkt, "example.com", fixedrand_fn, &fr);
	/* decode: see harness helper qinit_harness_decode_sni() */
	if (qinit_harness_decode_sni(pkt, 1200, "example.com"))
		printf("PASS round_trip\n");
	else { printf("FAIL round_trip\n"); fails++; }
}
```

Implement `qinit_harness_decode_sni` in `qinit_kat.c` using the harness's `aes128_*`, `sha256`, `qinit_derive_initial_keys`, and a local GCM-open (CTR + GHASH verify). This decoder is intentionally independent of the seal path so a bug in either surfaces.

- [ ] **Step 3: Run to verify it fails**

Run: `cd tests/imitate && make qinit_kat`
Expected: link error — `undefined reference to qinit_build`.

- [ ] **Step 4: Implement `qinit_build` in `src/qinit.c`**

Port `buildQUICInitial` from the Go oracle. Sequence (fixed-1200, `pnLen=4`):
1. Draw via `rand`: `dcid[8]`, `scid[8]`, `pn[4]` (in that order).
2. `qinit_derive_initial_keys(dcid, 8, key, iv, hp)`.
3. Build ClientHello (draws key_share pub then ch random via the same `rand`), wrap in CRYPTO frame.
4. `headerLen = 1+4+1+8+1+8+1+2+4 = 30`; `payloadLen = 1200 - 30 - 16 = 1154`; copy crypto frame into a 1154-byte payload region (trailing zeros = PADDING frames).
5. `lengthField = pnLen + payloadLen + 16 = 1174` → fits the 2-byte varint (`0x4496`).
6. Header bytes: `0xC3`, version `0x00000001`, `u8`-len dcid, `u8`-len scid, token-len `0x00`, varint(`lengthField`), record `pnOffset`, then `pn[4]`.
7. Nonce: `iv` with the last 4 bytes XOR `pn`.
8. `qinit_aes128_gcm_seal(key, nonce, hdr, headerLen, payload, payloadLen, out_after_hdr)` → writes ciphertext+tag right after the header in `buf`.
9. Header protection: `sample = buf[pnOffset+4 .. +16]`; `mask = AES_hp(sample)`; `buf[0] ^= mask[0] & 0x0f`; `buf[pnOffset+i] ^= mask[1+i]` for `i in 0..3`.
10. Return 0.

Stack scratch is small (key/iv/hp/nonce/sample + a ClientHello scratch buffer of a few hundred bytes). Keep the ClientHello scratch a fixed `u8 ch[512]` or smaller and bound it; stay within the 2048 frame budget (split into a helper if needed so no single frame exceeds it).

- [ ] **Step 5: Run to verify both tests pass**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS golden_vector` (byte-exact C↔Go) and `PASS round_trip` (SNI recovered). This is the maximum-guarantee Layer-2 gate.

- [ ] **Step 6: Style + commit**

```bash
cd src && make style && cd ..
git add src/qinit.h src/qinit.c tests/imitate/qinit_kat.c
git commit -m "feat(qinit): full QUIC Initial assembly + header protection; golden-vector + round-trip green"
```

---

## Phase 4 — Modifier-model `ctx` extension + tag wiring + in-kernel selftests

### Task 10: Add `void *ctx` to the junk modifier model (UAF-sensitive — copy semantics)

**Files:**
- Modify: `src/junk.h`, `src/junk.c`

This is the **highest-risk change** (CLAUDE.md UAF-sensitive path). Pure refactor: no new tag yet, so build + existing tests must stay green. Copy semantics throughout — tag and each mod own independent `kstrdup`-ed copies; teardown is symmetric; no pointer is ever shared across the tag/mod boundary.

**Interfaces:**
- Produces:
  ```c
  typedef void (*jp_modifier_func)(char *buf, int len, struct wg_peer *peer, void *ctx);
  struct jp_tag      { ...; void *ctx; };
  struct jp_modifier { ...; void *ctx; };
  ```

- [ ] **Step 1: Extend the types in `src/junk.h`**

Change the typedef and add `ctx` fields:

```c
typedef void(*jp_modifier_func)(char*, int, struct wg_peer*, void*);

struct jp_tag
{
    u8* pkt;
    jp_modifier_func func;
    struct list_head head;
    int pkt_size;
    void* ctx;          /* opaque per-tag data (e.g. qinit SNI); kstrdup-owned */
};

struct jp_modifier
{
    jp_modifier_func func;
    char* buf;
    int buf_len;
    void* ctx;          /* independent kstrdup copy of the tag's ctx */
};
```

- [ ] **Step 2: Add the unused `void *ctx` param to all 9 existing modifiers in `src/junk.c`**

Update signatures (bodies ignore `ctx`): `pkt_counter_modifier`, `unix_time_modifier`, `random_byte_modifier`, `random_char_modifier`, `random_digit_modifier`, `imitate_quic_modifier`, `imitate_dns_modifier`, `imitate_stun_modifier`, `imitate_sip_modifier`. Each becomes e.g.:

```c
static void pkt_counter_modifier(char* buf, int len, struct wg_peer *peer, void *ctx) {
```

- [ ] **Step 3: Free `ctx` in `jp_tag_free`**

```c
void jp_tag_free(struct jp_tag* tag) {
    kfree(tag->pkt);
    kfree(tag->ctx);
}
```

- [ ] **Step 4: Copy `ctx` tag→mod and free mod copies in `jp_spec_setup`/`jp_spec_free`**

In `jp_spec_setup`'s reverse loop, when materializing a mod, deep-copy `ctx`:

```c
    if (tag->func) {
        mod = spec->mods + spec->mods_size;
        mod->func = tag->func;
        mod->buf = spec->pkt + spec->pkt_size;
        mod->buf_len = tag->pkt_size;
        if (tag->ctx) {
            mod->ctx = kstrdup(tag->ctx, GFP_KERNEL);
            if (!mod->ctx) {       /* tag still owns tag->ctx; freed by the
                                    * unconditional cleanup tail below */
                err = -ENOMEM;
                goto error;
            }
        }
        spec->mods_size++;
    }
```

In `jp_spec_free`, free each mod's `ctx` before freeing the array:

```c
void jp_spec_free(struct jp_spec *spec) {
    int i;
    kfree(spec->desc);
    spec->desc = NULL;
    kfree(spec->pkt);
    spec->pkt = NULL;
    for (i = 0; i < spec->mods_size; i++)
        kfree(spec->mods[i].ctx);
    kfree(spec->mods);
    spec->mods = NULL;
    spec->pkt_size = 0;
    spec->mods_size = 0;
}
```

> **Lifetime invariant (do not deviate):** `tag->ctx` and each `mod->ctx` are *independent* heap copies. `jp_tag_free` frees the tag's copy (runs for every tag on both success and error paths via the `error:` tail). `jp_spec_free` frees the mods' copies. No pointer-move, no `tag->ctx = NULL` dance — that alternative invites the double-free the review (F2) flagged.

- [ ] **Step 5: Update the `jp_spec_applymods` call site**

```c
        if(mod->func)
            mod->func(mod->buf, mod->buf_len, peer, mod->ctx);
```

- [ ] **Step 6: Build (debug) + run existing imitate tests to verify no regression**

Run:
```bash
cd src && make module-debug 2>&1 | tail -5
cd ../tests/imitate && make test && make test-qinit
```
Expected: module builds clean; existing imitate vectors PASS; `qinit_kat` still `ALL PASS`.

- [ ] **Step 7: Style + commit**

```bash
cd src && make style && cd ..
git add src/junk.h src/junk.c
git commit -m "refactor(junk): add opaque void *ctx to modifier model (copy semantics)"
```

---

### Task 11: `qinit` tag parser + modifier + exclusivity + Kbuild wiring

**Files:**
- Modify: `src/qinit.c` (kernel-only `qinit_rand_getrandom`), `src/junk.c`, `src/Kbuild`

**Interfaces:**
- Consumes: `qinit_build`, `qinit_rand_getrandom`, `QINIT_DATAGRAM_LEN`.
- Produces: the `qinit` keyword handled in `jp_parse_tags`, an ispec that is qinit-exclusive.

- [ ] **Step 1: Implement the kernel randomness wrapper in `src/qinit.c`**

At the bottom of `qinit.c`, under the kernel guard:

```c
#ifdef __KERNEL__
void qinit_rand_getrandom(void *rctx, u8 *out, int n)
{
	(void)rctx;
	get_random_bytes(out, n);
}
#endif
```

- [ ] **Step 2: Add `qinit.o`, `crypto/aes.o`, `crypto/sha256.o` to `src/Kbuild`**

Append to the `amneziawg-y :=` line: ` qinit.o crypto/aes.o crypto/sha256.o`. (These vendored objects build unconditionally — no `CONFIG_CRYPTO_*`, no zinc perlasm machinery.)

- [ ] **Step 3: Add `parse_qinit_tag` + `qinit_modifier` to `src/junk.c`**

Add `#include "qinit.h"` near the top. Then:

```c
static void qinit_modifier(char *buf, int len, struct wg_peer *peer, void *ctx)
{
	(void)len;
	(void)peer;
	qinit_build((u8 *)buf, (const char *)ctx, qinit_rand_getrandom, NULL);
}

static int parse_qinit_tag(char *val, struct list_head *head)
{
	struct jp_tag *tag;
	int len;

	if (!val)
		return -EINVAL;
	while (*val == ' ')           /* trim leading spaces, mirrors Go TrimSpace */
		val++;
	len = strlen(val);
	while (len > 0 && val[len - 1] == ' ')
		val[--len] = '\0';
	if (len == 0 || len > 255)    /* non-empty SNI, <= 255 bytes */
		return -EINVAL;

	tag = kzalloc(sizeof(*tag), GFP_KERNEL);
	if (!tag)
		return -ENOMEM;

	tag->ctx = kstrdup(val, GFP_KERNEL);
	if (!tag->ctx) {
		kfree(tag);
		return -ENOMEM;
	}
	tag->pkt_size = QINIT_DATAGRAM_LEN;
	tag->func = qinit_modifier;

	list_add(&tag->head, head);
	return 0;
}
```

- [ ] **Step 4: Wire the `qinit` keyword into `jp_parse_tags`**

Add to the `if (!strcmp(key, ...))` chain (alongside `q`/`dns`/`stun`/`sip`):

```c
        else if (!strcmp(key, "qinit")) {
            err = parse_qinit_tag(val, head);
            if (err)
                return err;
        }
```

- [ ] **Step 5: Enforce qinit-exclusivity in `jp_spec_setup`**

A qinit datagram is self-contained; mixing it with any other tag corrupts it. After `jp_parse_tags` succeeds and the tag list is built, reject a mixed ispec. In the existing counting loop, track whether any tag is qinit and the total tag count:

```c
    int ntags = 0, nqinit = 0;
    list_for_each_entry(tag, &head, head) {
        pkt_size += tag->pkt_size;
        if (tag->func)
            ++mods_size;
        ++ntags;
        if (tag->func == qinit_modifier)
            ++nqinit;
    }
    if (nqinit && ntags != 1) {   /* qinit must be the sole tag in its ispec */
        err = -EINVAL;
        goto error;
    }
```

(`qinit_modifier` is `static` in `junk.c`, so the comparison is in-file — no export needed.)

- [ ] **Step 6: Build debug + smoke-test parsing via netns harness presence**

Run:
```bash
cd src && make module-debug 2>&1 | tail -5 && make style
```
Expected: clean build, clean style.

- [ ] **Step 7: KASAN/ASan on the `ctx` lifetime**

Exercise set/reset/replace of qinit tags. Userspace ASan path (interim oracle per spec §8, given the `prandom_*` debug-build gap):
```bash
cd tests/imitate && make CFLAGS="-O1 -g -fsanitize=address -I. -I../../src" qinit_kat && ./qinit_kat
```
Expected: `ALL PASS`, no ASan reports. (In-kernel KASAN is exercised end-to-end in Task 13.)

- [ ] **Step 8: Commit**

```bash
git add src/qinit.c src/junk.c src/Kbuild
git commit -m "feat(qinit): qinit I-packet tag (parser, modifier, exclusivity, Kbuild)"
```

---

### Task 12: In-kernel selftest wiring (`src/selftest/qinit.c`)

**Files:**
- Create: `src/selftest/qinit.c`
- Modify: `src/qinit.c` (include the selftest under debug), `src/main.c`, `src/qinit.h`

Mirror the `selftest/counter.c` pattern: a `bool qinit_selftest(void)` `#include`d into a TU and called from `wg_mod_init` under `CONFIG_AMNEZIAWG_DEBUG`. It runs the same KATs as the userspace harness (primitives + RFC 9001 A.1 + the embedded golden vector), proving the in-kernel build of the same source is correct across kernel versions via `make test-qemu`.

- [ ] **Step 1: Declare the selftest in `src/qinit.h`**

```c
#ifdef CONFIG_AMNEZIAWG_DEBUG
bool qinit_selftest(void);
#endif
```

- [ ] **Step 2: Write `src/selftest/qinit.c`**

Embed the golden vector and pinned stream as `static const u8[]` arrays (generate the C arrays from the committed `testdata/*.bin` with `xxd -i`), and assert: FIPS-197 AES, SHA-256, RFC 4231 HMAC, RFC 5869 Extract, RFC 9001 A.1 keys, and `qinit_build`-equals-golden-vector. Use `pr_err` on mismatch and return `false`. Structure:

```c
// SPDX-License-Identifier: GPL-2.0
#ifdef CONFIG_AMNEZIAWG_DEBUG
/* #include'd into qinit.c; uses its static helpers + the public KAT entries. */

static const u8 qinit_kat_rand[84] = { /* xxd -i of testdata/qinit_rand.bin */ };
static const u8 qinit_kat_vector[1200] = { /* xxd -i of testdata/qinit_vector.bin */ };

static void qinit_selftest_rand(void *rctx, u8 *out, int n)
{
	int *off = rctx, i;
	for (i = 0; i < n; i++)
		out[i] = (*off < 84) ? qinit_kat_rand[(*off)++] : 0;
}

bool qinit_selftest(void)
{
	u8 buf[QINIT_DATAGRAM_LEN];
	int off = 0;
	/* ... AES/SHA/HMAC/HKDF/RFC9001 asserts as in qinit_kat.c ... */
	qinit_build(buf, "example.com", qinit_selftest_rand, &off);
	if (memcmp(buf, qinit_kat_vector, QINIT_DATAGRAM_LEN)) {
		pr_err("qinit selftest: golden vector mismatch\n");
		return false;
	}
	return true;
}
#endif
```

- [ ] **Step 3: `#include` the selftest at the bottom of `src/qinit.c`**

```c
#ifdef CONFIG_AMNEZIAWG_DEBUG
#include "selftest/qinit.c"
#endif
```

- [ ] **Step 4: Call it from `src/main.c`**

Extend the existing selftest gate in `wg_mod_init`:

```c
	if (!wg_allowedips_selftest() || !wg_packet_counter_selftest() ||
	    !wg_ratelimiter_selftest() || !qinit_selftest())
		return -ENOTRECOVERABLE;
```

Add `#include "qinit.h"` to `main.c` if not already present. (Under non-debug builds `qinit_selftest` is absent — guard the call with the same `CONFIG_AMNEZIAWG_DEBUG` the existing selftests use, matching `main.c`'s current pattern.)

- [ ] **Step 5: Build debug + load to run the selftest**

Run:
```bash
cd src && make module-debug 2>&1 | tail -5 && make style
```
Expected: clean build + style. (Actual load/selftest execution runs under `make test-qemu` in Task 13.)

- [ ] **Step 6: Commit**

```bash
git add src/selftest/qinit.c src/qinit.c src/qinit.h src/main.c
git commit -m "test(qinit): in-kernel selftest (primitive KATs + RFC 9001 + golden vector)"
```

---

## Phase 5 — Independent interop + randomized property tests

### Task 13: Layer-3 interop (aioquic/tshark) + Layer-4 randomized property test

**Files:**
- Modify: `tests/imitate/qinit_kat.c` (Layer-4 property test)
- Create: `tests/imitate/qinit_interop.py` (Layer-3 independent decode)

Layer 3 uses decoders **we did not write** to catch "C and Go agree but are both wrong about the spec." Layer 4 generates N datagrams with real random inputs to catch varint/length edge cases the fixed vectors miss.

- [ ] **Step 1: Add the Layer-4 randomized property test to `qinit_kat.c`**

Generate N=256 datagrams with a non-deterministic rand source (a simple LCG seeded from a CLI arg or `time`-free counter is fine for userspace), and assert each decodes via the harness decoder and recovers SNI `example.com`:

```c
static void test_property(void)
{
	u8 pkt[1200];
	u32 s = 0x1234567u;
	int i, ok = 1;
	for (i = 0; i < 256; i++) {
		struct lcgrand lr = { .s = s + i*2654435761u };
		qinit_build(pkt, "example.com", lcgrand_fn, &lr);
		if (!qinit_harness_decode_sni(pkt, 1200, "example.com")) { ok = 0; break; }
	}
	if (ok) printf("PASS property_256\n"); else { printf("FAIL property_256 at iter\n"); fails++; }
}
```

(`lcgrand_fn` is a tiny harness-local PRNG — distinct from production; only its *decodability* is asserted, not specific bytes.)

- [ ] **Step 2: Run to verify the property test passes**

Run: `cd tests/imitate && make qinit_kat && ./qinit_kat`
Expected: `PASS property_256`.

- [ ] **Step 3: Write `tests/imitate/qinit_interop.py` (independent decode via aioquic)**

A standalone script that builds one datagram by invoking the harness with the pinned stream (or reads `testdata/qinit_vector.bin`), then uses **aioquic** to derive Initial keys, remove header protection, AEAD-open, and parse the TLS ClientHello — asserting `server_name == example.com` and ALPN `h3`. Add a `tshark -r <pcap> -Y quic` fallback assertion that the SNI field dissects. Gate on tool availability (skip with a clear message if aioquic/tshark absent — log the skip, do not silently pass).

- [ ] **Step 4: Run the interop decode against the committed golden vector**

Run: `cd tests/imitate && python3 qinit_interop.py testdata/qinit_vector.bin`
Expected: prints recovered `SNI=example.com ALPN=h3`, exit 0 (or a clear SKIP if aioquic is not installed).

- [ ] **Step 5: Commit**

```bash
git add tests/imitate/qinit_kat.c tests/imitate/qinit_interop.py
git commit -m "test(qinit): Layer-3 aioquic/tshark interop + Layer-4 randomized property test"
```

---

## Phase 6 — End-to-end netns + cross-kernel + KASAN under load

### Task 14: netns interop + `make test-qemu` + KASAN under load

**Files:**
- Modify: `src/tests/imitate-netns.sh`

End-to-end: a real `i1=<qinit example.com>` against a **vanilla** peer must (a) be dropped by the peer as undecryptable junk (no receive-path change), and (b) leave the tunnel handshaking normally.

- [ ] **Step 1: Add a qinit case to `src/tests/imitate-netns.sh`**

Mirror the existing imitate netns cases: bring up two namespaces with the module loaded, set `awg set <dev> i1='<qinit example.com>'` on the sender, generate handshake initiations, capture the wire bytes on the peer side, and assert: the captured I-packet is 1200 bytes and dissects as a QUIC Initial with SNI `example.com` (`tshark -Y quic` if available), the peer logs/drops it without matching the magic header, and a subsequent real handshake still completes (`awg show <dev> latest-handshakes` advances). Keep it consistent with the existing test's helper functions and skip-if-missing-tool conventions.

- [ ] **Step 2: Run the netns test**

Run: `cd src && make module-debug && cd .. && sudo ./src/tests/imitate-netns.sh` (or `make test` per the existing entry point).
Expected: the qinit case PASSES — peer drops the decoy as junk, tunnel handshakes.

- [ ] **Step 3: Run cross-kernel selftests under QEMU**

Run: `cd src && make test-qemu 2>&1 | tail -20`
Expected: the in-kernel `qinit_selftest` (Task 12) passes across the QEMU kernel matrix — crypto math is kernel-version-independent (vendored, no `CONFIG_CRYPTO_*`).

- [ ] **Step 4: KASAN under load on the `ctx` lifetime**

Repeatedly set/reset/replace `i1`–`i5` qinit tags under the debug build to exercise the §5.3 lifetime:
```bash
# under make module-debug (KASAN), in a netns loop:
for i in $(seq 1 200); do
  awg set <dev> i1='<qinit example.com>'
  awg set <dev> i1='<qinit cloudflare.com>'
  awg set <dev> i1=''
done
dmesg | grep -i kasan   # expect: no reports
```
Expected: no KASAN reports. (If the pre-existing `prandom_*` debug-build gap blocks an in-kernel KASAN run on 6.x/7.x, fall back to the Task 11 ASan run as the interim memory oracle and note it in the commit.)

- [ ] **Step 5: Commit**

```bash
git add src/tests/imitate-netns.sh
git commit -m "test(qinit): netns end-to-end vs vanilla peer + cross-kernel + KASAN"
```

---

## Self-Review

**Spec coverage:**

- §1 Goal / §5.1 builder API → Tasks 7–9 (`qinit_build`, injectable rand, fixed 1200). ✓
- §5.2 vendored primitives (`aes.c`, `sha256.c`) → Tasks 1–2; HMAC/HKDF/GCM in `qinit.c` → Tasks 3–4. ✓
- §5.3 `ctx` extension (copy semantics, all 9 modifiers, symmetric free) → Task 10. ✓
- §5.4 tag wiring (`qinit` keyword, `parse_qinit_tag`, `qinit_modifier`, exclusivity, `pkt_size` guard) → Task 11. ✓
- §6 data flow / §7 context → exercised in Tasks 11, 14 (process-context, lock-held send path unchanged). ✓
- §8 Layer 1 KATs → Tasks 1–4; Layer 2 (RFC 9001 A.1 + golden vector + round-trip) → Tasks 7, 9; Layer 3 interop → Task 13; Layer 4 property → Task 13; cross-kernel + KASAN → Task 14. ✓
- §8 Go refactor + committed golden vector + Go drift guard → Tasks 5–6. ✓
- §9 files touched → covered across all tasks (incl. `src/selftest/qinit.c` → Task 12). ✓
- §10 phasing → plan phases 1–6 map 1:1 to spec phases 1–6. ✓
- §11 risks: GHASH/GCM (Task 4 NIST KAT + Task 9 golden vector), `ctx` lifetime (Tasks 10/11/14 KASAN/ASan), `prandom_*` gap (Task 14 fallback noted). ✓
- §3 non-goals respected: no receive-path change, no ABI/netlink change, no tools change, no JA3 fingerprinting, no Tiers 1–3 behavior change. ✓

**Type consistency:** `qinit_rand_fn` signature, `qinit_build`/`qinit_derive_initial_keys`/`qinit_aes128_gcm_seal`/`qinit_hkdf_*`/`qinit_hmac_sha256` signatures, `aes128_ctx`/`sha256_ctx` and their APIs, and the `jp_modifier_func` `void *ctx` extension are used identically across all referencing tasks. The 84-byte pinned-stream layout and draw order are stated once (Global Constraints) and reused verbatim in Tasks 6, 9, 12. ✓

**Placeholder scan:** Standardized-primitive internals (AES S-box, SHA-256 round code, GHASH multiply) are deliberately specified by exact API + exact published KAT + normative reference per the stated convention, not as vague TODOs — each has a byte-exact acceptance gate. All project-specific code (port, `junk.c`, Kbuild, Go, harness, netns) is given as complete literal code. ✓
