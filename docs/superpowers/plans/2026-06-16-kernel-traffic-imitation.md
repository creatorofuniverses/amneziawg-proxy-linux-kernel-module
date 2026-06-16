# Kernel Traffic Imitation (Tiers 1–3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the client-side traffic-imitation feature (S-padding, junk packets, and I-packets shaped as QUIC/DNS/STUN/SIP) from the Go fork to the C kernel module, byte-exact with the Go oracle, Tiers 1–3.

**Architecture:** A new allocation-free, FP-free translation unit `src/imitate.c` implements a glibc-LCG PRNG and four protocol writers, validated in userspace against the Go fork's golden vectors before any kernel change. The fillers then replace `get_random_bytes` at three S-padding sites, one junk site, and (as new `junk.c` tags) the I-packet path. A device-global `imitate_protocol` selector reaches the kernel via a new netlink attribute, wired end-to-end through the `amneziawg-tools-proxy` fork.

**Tech Stack:** C (kernel out-of-tree module, Linux kernel coding style), kbuild, Go + Rust (vector generation in the `amneziawg-go-proxy` repo), netlink/libmnl (tools), `ip netns` (interop tests).

## Global Constraints

- **Byte-exactness:** `imitate_fill_prefix` / `imitate_fill_whole` must reproduce the Go output (`amneziawg-go-proxy/device/obf_imitate.go`) byte-for-byte. The per-protocol LCG draw order must not change. The golden vectors are the test of record.
- **PRNG constants (verbatim):** LCG `state = state*1103515245u + 12345u` (u32 wrap); FNV-1a offset `0x811c9dc5`, prime `0x01000193`.
- **Writers are allocation-free and floating-point-free** — safe in `GFP_ATOMIC`/softirq (the `send.c:260` transport path).
- **Backward compatibility:** `imitate_proto == IMITATE_NONE` (the default) must preserve the exact current `get_random_bytes` behavior at every call site.
- **Attribute-number contract:** `WGDEVICE_A_IMITATE_PROTOCOL` must have the identical enum value in the kernel `src/uapi/wireguard.h` and the tools `src/uapi/linux/linux/wireguard.h`. Both get an inline comment pointing at the other.
- **`imitate_proto` governs mechanisms A and B only.** Mechanism C (I-packet tags) bakes the proto into the tag/modifier and is independent of the device selector.
- **No uninitialized reads:** at the two `socket.c` sites the prefix fill MUST run after the message bytes are placed (see Task 9). Seeding uninitialized skb memory is forbidden (KMSAN / info-leak).
- **Style:** Linux kernel coding style (tabs, SPDX `GPL-2.0` headers); `make style` (checkpatch) must pass on new C. Commits follow Conventional Commits; the repo commits directly on `master`.
- **Repos:** three working trees — `amneziawg-go-proxy` (vectors), `amneziawg-proxy-linux-kernel-module` (the module), `amneziawg-tools-proxy` (config). Each task notes its repo.

---

## File Structure

| File | Repo | Responsibility |
|---|---|---|
| `device/obf_imitate_whole_gen_test.go` | go | Test-driven generator: emit `whole` golden rows (Go-only oracle) |
| `device/testdata/imitate_vectors.txt` | go | Prefix (Rust) + whole (Go) vectors |
| `device/obf_imitate_golden_test.go` | go | Parse both row kinds; self-check whole rows |
| `src/imitate.h` | kernel | Public API + `enum imitate_proto` |
| `src/imitate.c` | kernel | PRNG + four writers + dispatch + parse/name |
| `tests/imitate/imitate_shim.h` | kernel | Userspace `u8/u16/u32/u64` typedefs |
| `tests/imitate/harness.c` | kernel | Loads vectors, asserts byte-exact |
| `tests/imitate/Makefile` | kernel | Builds + runs the harness |
| `src/Kbuild` | kernel | Add `imitate.o` |
| `src/device.h` | kernel | `imitate_proto`, `imitate_junk_counter` |
| `src/uapi/wireguard.h` | kernel | `WGDEVICE_A_IMITATE_PROTOCOL` |
| `src/netlink.c` | kernel | Parse/dump the attribute |
| `src/socket.c`, `src/send.c` | kernel | Mechanism A + B call sites |
| `src/junk.c` | kernel | Mechanism C tags/modifiers |
| `tests/imitate-netns.sh` | kernel | Interop anchor |
| `src/uapi/linux/linux/wireguard.h` | tools | Matching enum |
| `src/ipc-linux.h` | tools | Send/parse the attribute over netlink |
| `src/containers.h`, `src/config.c` | tools | (already done in `fa52332`) |

---

## Task 1: Whole-fill golden vectors (F1)

**Repo:** `amneziawg-go-proxy`. Closes the F1 gap — the existing vectors are prefix-only, so mechanisms B/C (and the DNS-whole / `imitate_junk_seed` paths) currently have no oracle. The whole path is a Go-only divergence (no Rust counterpart), so it is generated from Go and self-checked by the Go test.

**Files:**
- Create: `amneziawg-go-proxy/device/obf_imitate_whole_gen_test.go` (test-driven generator)
- Modify: `amneziawg-go-proxy/tools/imitate-vectors/regen.sh`
- Modify: `amneziawg-go-proxy/device/obf_imitate_golden_test.go`
- Modify (regenerated): `amneziawg-go-proxy/device/testdata/imitate_vectors.txt`

**Interfaces:**
- Produces: appended lines of the form `<proto> whole <len> <seed_hex> <output_hex>` (5 fields; `seed_hex` = 8 hex digits of the `u32` seed). Consumed by Task 7's harness and this task's Go test.

- [ ] **Step 1: Add a `whole`-row parser branch to the Go golden test (failing)**

In `device/obf_imitate_golden_test.go`, replace the fixed `len(fields) != 4` handling so a 5-field `whole` row is verified via `imitateFillWhole`. Add this inside the scan loop, before the existing 4-field block:

```go
		if len(fields) == 5 && fields[1] == "whole" {
			proto, ok := protoFromName(fields[0])
			if !ok {
				t.Fatalf("unknown proto %q", fields[0])
			}
			length, err := strconv.Atoi(fields[2])
			if err != nil {
				t.Fatalf("bad len %q: %v", fields[2], err)
			}
			seed64, err := strconv.ParseUint(fields[3], 16, 32)
			if err != nil {
				t.Fatalf("bad seed hex %q: %v", fields[3], err)
			}
			want, err := hex.DecodeString(fields[4])
			if err != nil {
				t.Fatalf("bad output hex: %v", err)
			}
			buf := make([]byte, length)
			imitateFillWhole(buf, uint32(seed64), proto)
			if hex.EncodeToString(buf) != hex.EncodeToString(want) {
				t.Errorf("%s whole len=%d: byte mismatch\n got %x\nwant %x", fields[0], length, buf, want)
			}
			n++
			continue
		}
```

- [ ] **Step 2: Write the whole-vector generator (test-driven)**

The whole-fill writers are unexported in package `device`, so the generator lives as a `go test` dumper in that package (no separate `main`). Create `device/obf_imitate_whole_gen_test.go`:

```go
package device

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestGenWholeVectors is a generator, not an assertion. Run explicitly:
//   go test ./device/ -run TestGenWholeVectors -gen-whole
// It appends `<proto> whole <len> <seed_hex> <output_hex>` rows to the fixture.
func TestGenWholeVectors(t *testing.T) {
	if os.Getenv("IMITATE_GEN_WHOLE") == "" {
		t.Skip("set IMITATE_GEN_WHOLE=1 to (re)generate whole vectors")
	}
	protos := []struct {
		name string
		p    imitateProto
	}{{"quic", imitateQUIC}, {"dns", imitateDNS}, {"stun", imitateSTUN}, {"sip", imitateSIP}}
	lens := []int{10, 16, 20, 32, 40, 64, 150, 200}
	counters := []uint64{1, 2, 3, 7, 42, 1000}

	f, err := os.OpenFile("testdata/imitate_vectors.txt", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, pr := range protos {
		for _, ln := range lens {
			for _, c := range counters {
				seed := imitateJunkSeed(c)
				buf := make([]byte, ln)
				imitateFillWhole(buf, seed, pr.p)
				fmt.Fprintf(f, "%s whole %d %08x %s\n", pr.name, ln, seed, hex.EncodeToString(buf))
			}
		}
	}
}
```

`regen.sh` (next step) is the single entry point that runs both the Rust prefix generator and this Go whole-row dumper.

- [ ] **Step 3: Extend `regen.sh` to append whole rows after the Rust prefix rows**

Append to `tools/imitate-vectors/regen.sh` (after the existing `cargo run ...` line and its echo):

```bash
echo "Appending whole-fill vectors (Go oracle)…"
( cd "$REPO_ROOT" && IMITATE_GEN_WHOLE=1 go test ./device/ -run TestGenWholeVectors -count=1 )
echo "Appended whole-fill vectors to $OUT"
```

- [ ] **Step 4: Regenerate and verify**

Run:
```bash
cd amneziawg-go-proxy && bash tools/imitate-vectors/regen.sh && go test ./device/ -run TestImitateGoldenVectors -count=1 -v
```
Expected: regen prints both messages; the test logs `verified N golden vectors` with N now including whole rows (≈128 prefix + 4×8×6 = 192 whole). PASS.

- [ ] **Step 5: Commit**

```bash
cd amneziawg-go-proxy
git add tools/imitate-vectors/regen.sh device/obf_imitate_golden_test.go device/obf_imitate_whole_gen_test.go device/testdata/imitate_vectors.txt
git commit -m "test(imitate): add whole-fill golden vectors for kernel port (F1)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: PRNG core + userspace harness skeleton

**Repo:** kernel module. Establishes `imitate.h`, the PRNG primitives, and the test harness that every writer task reuses. No protocol writers yet.

**Files:**
- Create: `src/imitate.h`
- Create: `src/imitate.c`
- Create: `tests/imitate/imitate_shim.h`
- Create: `tests/imitate/harness.c`
- Create: `tests/imitate/Makefile`

**Interfaces:**
- Produces:
  - `enum imitate_proto { IMITATE_NONE, IMITATE_QUIC, IMITATE_DNS, IMITATE_STUN, IMITATE_SIP };`
  - `u32 imitate_fnv1a_seed(const u8 *payload, int len);`
  - `u32 imitate_junk_seed(u64 counter);`
  - `void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto p);`
  - `void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto p);`
  - `enum imitate_proto imitate_proto_parse(const char *s);`
  - `const char *imitate_proto_name(enum imitate_proto p);`

- [ ] **Step 1: Write `src/imitate.h`**

```c
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
```

- [ ] **Step 2: Write `src/imitate.c` core (PRNG + dispatch stubs)**

```c
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

static u32 next_lcg(u32 *state)
{
	u32 v = *state;

	*state = lcg_step(*state);
	return v;
}

static void put_be16(u8 *p, u16 v)
{
	p[0] = (u8)(v >> 8);
	p[1] = (u8)v;
}

static void put_be32(u8 *p, u32 v)
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
```

- [ ] **Step 3: Write `tests/imitate/imitate_shim.h`**

```c
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IMITATE_SHIM_H
#define IMITATE_SHIM_H
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif
```

- [ ] **Step 4: Write `tests/imitate/harness.c`**

```c
// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "imitate_shim.h"
#include "imitate.h"

static enum imitate_proto proto_of(const char *s)
{
	if (!strcmp(s, "quic")) return IMITATE_QUIC;
	if (!strcmp(s, "dns"))  return IMITATE_DNS;
	if (!strcmp(s, "stun")) return IMITATE_STUN;
	if (!strcmp(s, "sip"))  return IMITATE_SIP;
	return IMITATE_NONE;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int unhex(const char *s, u8 *out, int max)
{
	int n = (int)strlen(s) / 2, i;

	if (n > max) return -1;
	for (i = 0; i < n; i++)
		out[i] = (u8)((hexval(s[2 * i]) << 4) | hexval(s[2 * i + 1]));
	return n;
}

/* Prefix row:  <proto> <pad> <payload_hex> <output_hex>      (4 fields)
 * Whole row:   <proto> whole <len> <seed_hex> <output_hex>   (5 fields) */
int main(int argc, char **argv)
{
	FILE *f;
	char line[8192];
	int pass = 0, fail = 0;

	if (argc < 2) { fprintf(stderr, "usage: harness <vectors.txt>\n"); return 2; }
	f = fopen(argv[1], "r");
	if (!f) { perror("fopen"); return 2; }

	while (fgets(line, sizeof(line), f)) {
		char proto[16], f2[16], lenstr[16], seedhex[16], outhex[8192], payhex[4096];
		u8 want[8192], got[8192], payload[4096], seedbuf[4];
		enum imitate_proto p;

		if (sscanf(line, "%15s %15s %15s %15s %8191s",
			   proto, f2, lenstr, seedhex, outhex) == 5 &&
		    !strcmp(f2, "whole")) {
			int len = atoi(lenstr);
			int wn = unhex(outhex, want, sizeof(want));
			u32 seed;

			if (unhex(seedhex, seedbuf, 4) != 4)
				continue;
			seed = ((u32)seedbuf[0] << 24) | ((u32)seedbuf[1] << 16) |
			       ((u32)seedbuf[2] << 8) | (u32)seedbuf[3];
			memset(got, 0, len);
			imitate_fill_whole(got, len, seed, p = proto_of(proto));
			if (wn == len && !memcmp(got, want, len)) pass++;
			else { fail++; fprintf(stderr, "FAIL %s whole len=%d\n", proto, len); }
			continue;
		}
		/* Prefix row: re-parse the 4-field layout. */
		if (sscanf(line, "%15s %15s %4095s %8191s",
			   proto, lenstr, payhex, outhex) == 4) {
			int pad = atoi(lenstr);
			int pn = unhex(payhex, payload, sizeof(payload));
			int wn = unhex(outhex, want, sizeof(want));
			int total = pad + pn;

			memset(got, 0, total);
			memcpy(got + pad, payload, pn);
			imitate_fill_prefix(got, total, pad, p = proto_of(proto));
			if (wn == total && !memcmp(got, want, total)) pass++;
			else { fail++; fprintf(stderr, "FAIL %s pad=%d\n", proto, pad); }
		}
	}
	fclose(f);
	fprintf(stderr, "pass=%d fail=%d\n", pass, fail);
	return fail ? 1 : 0;
}
```

- [ ] **Step 5: Write `tests/imitate/Makefile`**

```make
# SPDX-License-Identifier: GPL-2.0
VECTORS ?= ../../../amneziawg-go-proxy/device/testdata/imitate_vectors.txt
CFLAGS  := -O2 -Wall -Wextra -Werror -I. -I../../src

harness: harness.c ../../src/imitate.c ../../src/imitate.h imitate_shim.h
	$(CC) $(CFLAGS) -o harness harness.c ../../src/imitate.c

.PHONY: test clean
test: harness
	./harness $(VECTORS)

clean:
	rm -f harness
```

- [ ] **Step 6: Build and run (expect zero pass, zero fail — stubs no-op)**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/tests/imitate && make test
```
Expected: compiles clean; prints `pass=0 fail=N` where N = number of vectors (all fail because writers are stubs). This proves the harness wiring and the vector path. Exit nonzero is fine here.

- [ ] **Step 7: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.h src/imitate.c tests/imitate/
git commit -m "feat(imitate): PRNG core + userspace golden harness scaffold

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: QUIC writer

**Repo:** kernel module. First protocol → first green vectors.

**Files:**
- Modify: `src/imitate.c`

**Interfaces:**
- Consumes: `lcg_step`, `next_lcg` (Task 2).
- Produces: `write_quic_short(u8 *buf, int padding, u32 seed)` (static); QUIC wired into both dispatchers.

- [ ] **Step 1: Add the QUIC writer above the dispatchers in `src/imitate.c`**

```c
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
```

- [ ] **Step 2: Wire QUIC into the two dispatchers (replace the stub bodies)**

```c
void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto p)
{
	u32 seed;

	if (padding == 0 || padding >= total_len)
		return;
	seed = imitate_fnv1a_seed(buf + padding, total_len - padding);
	switch (p) {
	case IMITATE_QUIC: write_quic_short(buf, padding, seed); break;
	default: break;
	}
}

void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto p)
{
	if (len <= 0)
		return;
	switch (p) {
	case IMITATE_QUIC: write_quic_short(buf, len, seed); break;
	default: break;
	}
}
```

- [ ] **Step 3: Run the harness, QUIC only**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/tests/imitate && make test 2>&1 | grep -E 'quic|pass='
```
Expected: no `FAIL quic …` lines. (Other protocols still FAIL — expected.)

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.c
git commit -m "feat(imitate): QUIC short-header writer, byte-exact vs Go

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: DNS writer (OPT response + NULL fallback + whole)

**Repo:** kernel module. Implements both seed paths (payload-TXID for prefix, seed-TXID for whole).

**Files:**
- Modify: `src/imitate.c`

**Interfaces:**
- Consumes: `put_be16` (unused here), `clamp_u16` (added here).
- Produces: `write_dns_msg`, `write_dns_opt_response`, `write_dns_null` (static); DNS wired into both dispatchers.

- [ ] **Step 1: Add `clamp_u16` and the DNS writers**

```c
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
```

- [ ] **Step 2: Add DNS to both dispatchers**

In `imitate_fill_prefix`'s switch, add:
```c
	case IMITATE_DNS: {
		u8 txid[2] = { 0, 0 };

		if (total_len - padding > 0) txid[0] = buf[padding];
		if (total_len - padding > 1) txid[1] = buf[padding + 1];
		write_dns_msg(buf, total_len, padding, txid);
		break;
	}
```
In `imitate_fill_whole`'s switch, add:
```c
	case IMITATE_DNS: {
		u8 txid[2] = { (u8)(seed >> 8), (u8)seed };

		write_dns_msg(buf, len, len, txid);
		break;
	}
```

- [ ] **Step 3: Run the harness, DNS only**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/tests/imitate && make test 2>&1 | grep -E 'dns|pass='
```
Expected: no `FAIL dns …` lines (prefix and whole).

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.c
git commit -m "feat(imitate): DNS OPT/NULL writer (prefix + whole), byte-exact

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: STUN writer

**Repo:** kernel module.

**Files:**
- Modify: `src/imitate.c`

**Interfaces:**
- Consumes: `next_lcg`, `put_be16`, `put_be32`.
- Produces: `write_stun(u8 *buf, int padding, u32 seed)` (static); wired into both dispatchers.

- [ ] **Step 1: Add the STUN writer**

```c
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
```

- [ ] **Step 2: Add STUN to both dispatchers**

`imitate_fill_prefix` switch: `case IMITATE_STUN: write_stun(buf, padding, seed); break;`
`imitate_fill_whole` switch: `case IMITATE_STUN: write_stun(buf, len, seed); break;`

- [ ] **Step 3: Run the harness, STUN only**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/tests/imitate && make test 2>&1 | grep -E 'stun|pass='
```
Expected: no `FAIL stun …` lines.

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.c
git commit -m "feat(imitate): STUN Binding Success writer, byte-exact

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: SIP writer

**Repo:** kernel module. The trickiest writer (string formatting + Content-Length search). The golden SIP vectors are the gate; on any byte mismatch, diff against `obf_imitate.go:writeSIP` line-by-line — the draw order and format strings must match exactly.

**Files:**
- Modify: `src/imitate.c`

**Interfaces:**
- Consumes: `next_lcg`, `IMITATE_SNPRINTF`.
- Produces: `write_sip(u8 *buf, int total, int padding, u32 seed)` (static); wired into both dispatchers.

- [ ] **Step 1: Add the decimal-digit helper and the SIP writer**

```c
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
```

> Draw-order gotcha: `cseq` uses `st` directly **after** the seven `next_lcg`
> draws — do not add an eighth draw. The `%08x` width and the single-vs-double
> space in `Content-Length:` are load-bearing for byte-exactness.

- [ ] **Step 2: Add SIP to both dispatchers**

`imitate_fill_prefix` switch: `case IMITATE_SIP: write_sip(buf, total_len, padding, seed); break;`
`imitate_fill_whole` switch: `case IMITATE_SIP: write_sip(buf, len, len, seed); break;`

- [ ] **Step 3: Run the full harness — all protocols must pass**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/tests/imitate && make test
```
Expected: `pass=N fail=0`, exit 0. This closes the byte-exactness gate for Tiers 1–3 (F1 satisfied: prefix + whole, all four protocols).

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.c
git commit -m "feat(imitate): SIP response writer, byte-exact (all vectors green)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Build into the module + device state + netlink attribute

**Repo:** kernel module. Compiles `imitate.c` into `amneziawg.ko`, adds device state, and the `WGDEVICE_A_IMITATE_PROTOCOL` netlink attribute (parse + dump). No call-site behavior change yet.

**Files:**
- Modify: `src/Kbuild`
- Modify: `src/device.h`
- Modify: `src/uapi/wireguard.h`
- Modify: `src/netlink.c`

**Interfaces:**
- Consumes: `imitate_proto_parse`, `imitate_proto_name`, `enum imitate_proto` (Task 2).
- Produces: `wg->imitate_proto` (`enum imitate_proto`), `wg->imitate_junk_counter` (`atomic64_t`); `WGDEVICE_A_IMITATE_PROTOCOL` enum.

- [ ] **Step 1: Add `imitate.o` to `src/Kbuild`**

Append `imitate.o` to the `amneziawg-y :=` object list (next to `junk.o magic_header.o`).

- [ ] **Step 2: Add device fields in `src/device.h`**

Add `#include "imitate.h"` near the other local includes, and inside `struct wg_device` (after `bool advanced_security;`):
```c
	enum imitate_proto imitate_proto;
	atomic64_t imitate_junk_counter;
```

- [ ] **Step 3: Add the netlink attribute enum in `src/uapi/wireguard.h`**

Insert before `__WGDEVICE_A_LAST`:
```c
	WGDEVICE_A_IMITATE_PROTOCOL, /* keep value == tools src/uapi/linux/linux/wireguard.h */
```

- [ ] **Step 4: Add the policy entry in `src/netlink.c`**

In `device_policy[]` (near the `WGDEVICE_A_I5` entry):
```c
	[WGDEVICE_A_IMITATE_PROTOCOL]	= { .type = NLA_NUL_STRING },
```

- [ ] **Step 5: Parse it in `wg_set_device` (after the `WGDEVICE_A_I5` block)**

```c
	if (info->attrs[WGDEVICE_A_IMITATE_PROTOCOL]) {
		wg->advanced_security = true;
		str = nla_strdup(info->attrs[WGDEVICE_A_IMITATE_PROTOCOL], GFP_KERNEL);
		if (!str) {
			ret = -ENOMEM;
			goto out;
		}
		wg->imitate_proto = imitate_proto_parse(str);
		kfree(str);
	}
```

- [ ] **Step 6: Emit it on dump (after the I1–I5 `nla_put_string` chain, ~line 463)**

Add a standalone put (outside the `||` chain) before the success path:
```c
	if (wg->imitate_proto != IMITATE_NONE &&
	    nla_put_string(skb, WGDEVICE_A_IMITATE_PROTOCOL,
			   imitate_proto_name(wg->imitate_proto)))
		goto err;
```
(Use the same `goto` label / pattern the surrounding dump code uses; match the existing error handling exactly.)

- [ ] **Step 7: Build the module**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/src && make module 2>&1 | tail -20
```
Expected: builds `amneziawg.ko` with no errors. Then `make style 2>&1 | tail` — no new checkpatch errors on `imitate.c`/`imitate.h`.

- [ ] **Step 8: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/Kbuild src/device.h src/uapi/wireguard.h src/netlink.c
git commit -m "feat(imitate): build imitate.c; add imitate_protocol netlink attr

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Tools fork — wire imitate_protocol over netlink

**Repo:** `amneziawg-tools-proxy`. The `ImitateProtocol` key already parses into `dev->imitate_protocol` + `WGDEVICE_HAS_IMITATE_PROTOCOL` (commit `fa52332`); this adds the kernel netlink set/get path.

**Files:**
- Modify: `src/uapi/linux/linux/wireguard.h`
- Modify: `src/ipc-linux.h`

**Interfaces:**
- Consumes: `dev->imitate_protocol`, `WGDEVICE_HAS_IMITATE_PROTOCOL` (existing).
- Produces: kernel-side set/get of `WGDEVICE_A_IMITATE_PROTOCOL`.

- [ ] **Step 1: Add the matching enum (same value as the kernel)**

In `src/uapi/linux/linux/wireguard.h`, insert before `__WGDEVICE_A_LAST`:
```c
	WGDEVICE_A_IMITATE_PROTOCOL, /* keep value == kernel src/uapi/wireguard.h */
```

- [ ] **Step 2: Send it in `kernel_set_device` (after the `WGDEVICE_HAS_I5` line, ~226)**

```c
		if (dev->flags & WGDEVICE_HAS_IMITATE_PROTOCOL)
			mnl_attr_put_strz(nlh, WGDEVICE_A_IMITATE_PROTOCOL, dev->imitate_protocol);
```

- [ ] **Step 3: Parse it on get (in `parse_device`, after the `WGDEVICE_A_I5` case, ~627)**

```c
	case WGDEVICE_A_IMITATE_PROTOCOL:
		if (!mnl_attr_validate(attr, MNL_TYPE_STRING)) {
			device->imitate_protocol = strdup(mnl_attr_get_str(attr));
			if (!device->imitate_protocol)
				return MNL_CB_ERROR;
			device->flags |= WGDEVICE_HAS_IMITATE_PROTOCOL;
		}
		break;
```
(Match the exact validation/return idiom used by the neighboring `WGDEVICE_A_I*` cases — copy their shape.)

- [ ] **Step 4: Build the tools**

Run:
```bash
cd amneziawg-tools-proxy/src && make 2>&1 | tail -20
```
Expected: `awg`/`wg` binary builds with no errors.

- [ ] **Step 5: Commit**

```bash
cd amneziawg-tools-proxy
git add src/uapi/linux/linux/wireguard.h src/ipc-linux.h
git commit -m "feat(imitate): send imitate_protocol over kernel netlink path

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Mechanism A — S-padding call sites (with F2 reorder)

**Repo:** kernel module. Replaces the three `get_random_bytes` S-padding sites. The two `socket.c` sites must fill **after** the payload is placed.

**Files:**
- Modify: `src/imitate.c`, `src/imitate.h` (add `wg_fill_padding` helper)
- Modify: `src/socket.c` (two sites)
- Modify: `src/send.c` (`encrypt_packet`, transport site)

**Interfaces:**
- Consumes: `imitate_fill_prefix`, `wg->imitate_proto`.
- Produces: `void wg_fill_padding(struct wg_device *wg, u8 *buf, int total_len, int padding);`

- [ ] **Step 1: Add `wg_fill_padding` declaration to `src/imitate.h`**

After the existing prototypes, guarded for kernel only (it needs `struct wg_device`):
```c
#ifdef __KERNEL__
struct wg_device;
void wg_fill_padding(struct wg_device *wg, u8 *buf, int total_len, int padding);
void wg_fill_junk(struct wg_device *wg, u8 *buf, int len);
#endif
```

- [ ] **Step 2: Implement the helpers in `src/imitate.c` (kernel-only block at end)**

```c
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
```

- [ ] **Step 3: Reorder + swap the two `socket.c` sites**

`wg_socket_send_buffer_to_peer` (replace lines 200–202):
```c
	junk = skb_put(skb, junk_size);
	skb_put_data(skb, buffer, len);
	wg_fill_padding(peer->device, junk, junk_size + len, junk_size);
```
`wg_socket_send_buffer_as_reply_to_skb` (replace lines 226–228):
```c
	junk = skb_put(skb, junk_size);
	skb_put_data(skb, buffer, len);
	wg_fill_padding(wg, junk, junk_size + len, junk_size);
```
Add `#include "imitate.h"` to `socket.c` if not already present.

- [ ] **Step 4: Swap the transport site in `send.c`**

`encrypt_packet` already has the payload present after `skb_push(header)`/`pskb_put(trailer)`. Thread the device in: change its signature to add `struct wg_device *wg` (or pass `enum imitate_proto`), update the one caller in `wg_packet_encrypt_worker` (it has `wg`), and replace line 260:
```c
	{
		u8 *jp = skb_push(skb, junk_size);

		wg_fill_padding(wg, jp, junk_size + (skb->len - junk_size), junk_size);
	}
```
Here `skb->len - junk_size` is the message length after the push; `total_len = skb->len`. Simpler equivalent: `wg_fill_padding(wg, skb->data, skb->len, junk_size);` since `skb->data` points at the junk after the push and `skb->len` is the full length. Use the `skb->data`/`skb->len` form. Add `#include "imitate.h"` to `send.c` if needed.

- [ ] **Step 5: Build + style + harness still green**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/src && make module 2>&1 | tail && make style 2>&1 | tail
cd ../tests/imitate && make test
```
Expected: module builds; checkpatch clean; harness `fail=0` (the userspace build of `imitate.c` ignores the `__KERNEL__` block, so it still compiles).

- [ ] **Step 6: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/imitate.c src/imitate.h src/socket.c src/send.c
git commit -m "feat(imitate): shape S-padding (mechanism A); reorder socket.c fill (F2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Mechanism B — junk packets

**Repo:** kernel module.

**Files:**
- Modify: `src/send.c` (`send.c:70`)

**Interfaces:**
- Consumes: `wg_fill_junk` (Task 9).

- [ ] **Step 1: Swap the junk fill at `send.c:70`**

Replace:
```c
			get_random_bytes(buffer, junk_packet_size);
```
with:
```c
			wg_fill_junk(wg, buffer, junk_packet_size);
```
(`wg` is in scope in `wg_packet_send_handshake_initiation`.)

- [ ] **Step 2: Build + style**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/src && make module 2>&1 | tail && make style 2>&1 | tail
```
Expected: clean build, no new checkpatch errors.

- [ ] **Step 3: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/send.c
git commit -m "feat(imitate): shape standalone junk packets (mechanism B)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Mechanism C — I-packet tags in junk.c

**Repo:** kernel module. Adds `<q N>`/`<dns N>`/`<stun N>`/`<sip N>` tags, mirroring `parse_rc_tag`/`random_char_modifier`. No struct changes.

**Files:**
- Modify: `src/junk.c`

**Interfaces:**
- Consumes: `imitate_fill_whole`, `imitate_junk_seed`, `peer->jp_packet_counter`.

- [ ] **Step 1: Add the modifiers + parsers in `src/junk.c`**

Add `#include "imitate.h"` at the top, then after `parse_rd_tag`:
```c
static void imitate_quic_modifier(char *buf, int len, struct wg_peer *peer)
{
	u32 seed = imitate_junk_seed(atomic_read(&peer->jp_packet_counter));

	imitate_fill_whole((u8 *)buf, len, seed, IMITATE_QUIC);
}

static void imitate_dns_modifier(char *buf, int len, struct wg_peer *peer)
{
	u32 seed = imitate_junk_seed(atomic_read(&peer->jp_packet_counter));

	imitate_fill_whole((u8 *)buf, len, seed, IMITATE_DNS);
}

static void imitate_stun_modifier(char *buf, int len, struct wg_peer *peer)
{
	u32 seed = imitate_junk_seed(atomic_read(&peer->jp_packet_counter));

	imitate_fill_whole((u8 *)buf, len, seed, IMITATE_STUN);
}

static void imitate_sip_modifier(char *buf, int len, struct wg_peer *peer)
{
	u32 seed = imitate_junk_seed(atomic_read(&peer->jp_packet_counter));

	imitate_fill_whole((u8 *)buf, len, seed, IMITATE_SIP);
}

static int parse_imitate_tag(char *val, struct list_head *head, jp_modifier_func func)
{
	struct jp_tag *tag;
	int len;

	if (!val || 0 > kstrtoint(val, 10, &len))
		return -EINVAL;
	tag = kzalloc(sizeof(*tag), GFP_KERNEL);
	if (!tag)
		return -ENOMEM;
	tag->pkt_size = len;
	tag->func = func;
	list_add(&tag->head, head);
	return 0;
}
```

- [ ] **Step 2: Register the four keys in `jp_parse_tags`**

After the `rd` branch, before the final `else return -EINVAL;`:
```c
		else if (!strcmp(key, "q")) {
			err = parse_imitate_tag(val, head, imitate_quic_modifier);
			if (err)
				return err;
		}
		else if (!strcmp(key, "dns")) {
			err = parse_imitate_tag(val, head, imitate_dns_modifier);
			if (err)
				return err;
		}
		else if (!strcmp(key, "stun")) {
			err = parse_imitate_tag(val, head, imitate_stun_modifier);
			if (err)
				return err;
		}
		else if (!strcmp(key, "sip")) {
			err = parse_imitate_tag(val, head, imitate_sip_modifier);
			if (err)
				return err;
		}
```

- [ ] **Step 3: Build + style**

Run:
```bash
cd amneziawg-proxy-linux-kernel-module/src && make module 2>&1 | tail && make style 2>&1 | tail
```
Expected: clean build, no new checkpatch errors.

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add src/junk.c
git commit -m "feat(imitate): I-packet imitation tags q/dns/stun/sip (mechanism C)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: netns interop anchor

**Repo:** kernel module. Proves the cosmetic/interop property end-to-end with a real loaded module.

**Files:**
- Create: `tests/imitate-netns.sh`

**Interfaces:** none (integration test).

- [ ] **Step 1: Write `tests/imitate-netns.sh`**

A self-contained two-namespace test: build + `insmod` the module, create a veth/tunnel pair, configure one side with `awg set wg0 imitate_protocol quic` and an `I1=<q 600>` decoy via the patched tools, bring up the tunnel against a peer configured **without** imitate, and assert `ping` + a small `iperf3`/`nc` transfer succeed (vanilla acceptance proves the cosmetic claim). Model it on the existing `tests/netns.sh` structure (reuse its namespace/veth scaffolding). Include a `tcpdump -w` capture of the veth for the manual realism check (Step 3).

```bash
#!/usr/bin/env bash
# Interop anchor for client-side traffic imitation (Tiers 1-3).
# Requires: built amneziawg.ko, patched awg tools on PATH, root.
set -euo pipefail
# ... namespace + veth setup mirroring tests/netns.sh ...
# side A (patched): awg set wg0 private-key <k> imitate_protocol quic \
#     i1 '<q 600>' peer <pubB> allowed-ips 0.0.0.0/0 endpoint <B>
# side B (vanilla AWG, no imitate): standard awg set
# assert: ip netns exec A ping -c3 <B-tunnel-ip>
# assert: small transfer over the tunnel succeeds
echo "PASS: patched sender interops with vanilla peer"
```

- [ ] **Step 2: Run it**

Run (as root):
```bash
cd amneziawg-proxy-linux-kernel-module && sudo bash tests/imitate-netns.sh
```
Expected: `PASS: patched sender interops with vanilla peer`. Repeat with `imitate_protocol` set on both sides (patched↔patched).

- [ ] **Step 3: Realism spot-check (manual, documented in the script header)**

Open the captured pcap in Wireshark; confirm outgoing packets classify as QUIC and the dissector consumes exactly the padding region, leaving `[magic header + ciphertext]` opaque. Compare against a real HTTP/3 capture.

- [ ] **Step 4: Commit**

```bash
cd amneziawg-proxy-linux-kernel-module
git add tests/imitate-netns.sh
git commit -m "test(imitate): netns interop anchor (patched sender <-> vanilla peer)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- §3.1 imitate.c (PRNG + writers) → Tasks 2–6. ✓
- §3.2 device state → Task 7. ✓
- §4.1 Mechanism A (3 sites, F2 reorder) → Task 9. ✓
- §4.2 Mechanism B → Task 10. ✓
- §4.3 Mechanism C → Task 11. ✓
- §5.1 kernel netlink attr → Task 7. ✓
- §5.2 tools wiring → Task 8. ✓
- §6.1 golden harness (F1 prefix + whole) → Tasks 1–6. ✓
- §6.2 netns interop → Task 12. ✓
- §6.3 realism spot-check → Task 12 Step 3. ✓
- §6.4 fuzz/tiny sizes → covered by the `pad=10/16` and `whole len=10` vectors exercised in Tasks 3–6 (writers guard `padding <= 0` and small-pad fallbacks). ✓
- §7 risks: F2 (Task 9 reorder), F3 (transport seeds from plaintext — Task 9 uses `skb->data`/`skb->len`, no reorder), F4 (Task 11 bakes proto per-tag), F5 (Task 8 correct header path; receive `>=` not touched). ✓

**Type consistency:** `imitate_fill_prefix(u8*, int total_len, int padding, enum imitate_proto)`, `imitate_fill_whole(u8*, int len, u32 seed, enum imitate_proto)`, `wg_fill_padding(struct wg_device*, u8*, int total_len, int padding)`, `wg_fill_junk(struct wg_device*, u8*, int len)`, `enum imitate_proto`/`WGDEVICE_A_IMITATE_PROTOCOL` — used identically across Tasks 2–11. ✓

**Placeholder scan:** writer C is complete; the only deferred manual step is the Wireshark realism check (inherently manual) and the netns scaffolding (delegated to the existing `tests/netns.sh` pattern, which exists in-repo). No "TODO"/"implement later" in code steps. ✓

**Known follow-up (out of scope):** Tier 4 `qinit` — separate Phase-2 spec.
