# Client-side traffic imitation — Tier 4 `qinit` (fake QUIC Initial + SNI)

- **Status:** approved design, not built
- **Date:** 2026-06-17
- **Scope:** `amneziawg-proxy-linux-kernel-module` (the feature) +
  `amneziawg-go-proxy` (test-only: a behavior-preserving randomness refactor of
  the oracle so it can emit a deterministic golden vector — see §8). **No
  `amneziawg-tools-proxy` change and no netlink/ABI change** (§4).
- **Phase:** Phase 2 of the client-imitation feature; Tiers 1–3 shipped on `master`
  (merged PR #1). This spec is the deferred Tier 4 from
  `docs/superpowers/specs/2026-06-16-kernel-traffic-imitation-design.md` §1, §9.6.
- **Reference implementation (oracle):** `amneziawg-go-proxy`
  (`device/obf_imitate_quic.go`).

## 1. Goal

Port Tier 4 / `qinit` from the Go fork to the C kernel module: an I-packet decoy
that is a complete, header-protected **QUIC v1 Initial datagram** (fixed 1200
bytes) carrying a TLS 1.3 ClientHello advertising a benign **SNI**. The QUIC
Initial keys derive from the public, fixed RFC 9001 §5.2 salt and a random
single-use Destination Connection ID, so **any observer can derive the keys and
read the SNI** — which is the point: it defeats cheap line-rate SNI filtering by
making the decoy look like a real browser opening an HTTP/3 connection to an
innocuous host.

Like Tiers 1–3, qinit is **sender-only and cosmetic**: a vanilla AmneziaWG/
WireGuard peer receives the datagram, fails to match the magic header, and drops
it as undecryptable junk (`src/receive.c`). It changes nothing on the receive
path and interops with a vanilla peer unchanged.

Tier 4 is delivered at **full structural parity** with the Go oracle: identical
TLS 1.3 ClientHello field layout (cipher suites, x25519 `key_share`, ALPN `h3`,
QUIC transport parameters with the `initial_source_connection_id` echo), the same
1200-byte Initial, and the same header-protection scheme. Only the random fields
(connection IDs, packet number, ClientHello randoms) differ per call, exactly as
in the oracle.

## 2. Why Tier 4 is different from Tiers 1–3

| Property | Tiers 1–3 | Tier 4 (`qinit`) |
| --- | --- | --- |
| Primitives | none (byte-poking PRNG) | AES-128-GCM, HKDF-SHA256, AES-ECB |
| Reproducibility | byte-exact with Go (golden vectors) | non-deterministic in production (random CIDs/PN/randoms); **made deterministic under pinned randomness** for the golden vector (§8) |
| Validation oracle | golden vector file | RFC 9001 A.1 key schedule + **byte-exact golden vector** (Go w/ injected randomness) + self-decrypt round-trip |
| Repos touched | 3 (kernel, go, tools) | **2** (kernel = feature; go = test-only oracle refactor); tools untouched |
| Netlink/ABI | new `WGDEVICE_A_IMITATE_PROTOCOL` | **none** (rides in existing `I1`–`I5` desc) |

The crypto primitives qinit needs do **not** exist in the in-tree `src/crypto/
zinc` (which has only ChaCha20, Poly1305, BLAKE2s, Curve25519). This spec adds
them as vendored software primitives (§5).

## 3. Non-goals

- No receive-path changes.
- No browser-accurate JA3/JA4 fingerprinting. The ClientHello is clean and
  parseable but its fingerprint is static — matching a specific browser is a
  deferred sub-tier (Go's `Ib`), explicitly out of scope here.
- No layer-4 (size/timing) coverage.
- No change to Tiers 1–3 behavior, the `imitate_protocol` selector, or the
  existing `q`/`dns`/`stun`/`sip` tags.
- No new netlink attribute and **no `amneziawg-tools-proxy` change** (§4).

## 4. Wire/control-plane integration — no ABI change

qinit is a per-tag **mechanism C** keyword, exactly like the existing
`q`/`dns`/`stun`/`sip` I-packet tags. Those are parsed from the `I1`–`I5`
description strings, which already travel over netlink via `WGDEVICE_A_I1..I5`
(`src/netlink.c:858+`) and are **opaque to the tools** — `amneziawg-tools-proxy`
forwards `i1=<qinit example.com>` verbatim without interpreting it.

Consequences:

- **No new netlink attribute.** The `WGDEVICE_A_IMITATE_PROTOCOL` enum (and all
  ordinals after `WGDEVICE_A_I5`) stay frozen, honoring the ABI contract noted in
  the Tiers 1–3 work.
- **No tools change.** Existing `awg set` / `awg show` round-trip the `qinit`
  desc string unchanged.
- The **feature** lands entirely in the kernel-module repo. The only other repo
  touched is `amneziawg-go-proxy`, and only for **test infrastructure** (a
  behavior-preserving randomness refactor of the oracle to emit a golden vector —
  §8); no production Go behavior changes.

## 5. Architecture

### 5.1 New translation unit: `src/qinit.c` + `src/qinit.h`

Mirrors Go's `device/obf_imitate_quic.go`. Kept **out of `src/junk.c`** so the
crypto-heavy code is isolated from the memory-safety-sensitive junk path
(`junk.c`/`magic_header.c`, per CLAUDE.md). Added to `src/Kbuild` `amneziawg-y`.

Contents (all mirroring the Go oracle byte-for-byte in structure):

- `hkdf_expand_label(secret, label, out, len)` — TLS 1.3 HKDF-Expand-Label
  (RFC 8446 §7.1) with the `"tls13 "` prefix and zero-length context.
- `derive_initial_keys(dcid, key[16], iv[12], hp[16])` — RFC 9001 §5.2 client
  Initial key derivation: `HKDF-Extract(salt=quic_v1_initial_salt, ikm=dcid)`
  → `"client in"` → `"quic key"`/`"quic iv"`/`"quic hp"`. **Argument order is
  load-bearing:** Extract takes the salt as the HMAC *key* and the DCID as the IKM
  (`initial_secret = HMAC-SHA256(key=salt, msg=dcid)`). Hand-rolled HKDF commonly
  swaps these; the RFC 9001 A.1 key-schedule test (§8 Layer 2) only passes if the
  order is correct.
- `build_client_hello(...)` — full TLS 1.3 ClientHello: `server_name`,
  `supported_versions` (0x0304), `supported_groups` (x25519), `key_share`
  (x25519, 32 random bytes), `signature_algorithms`, ALPN `h3`,
  `quic_transport_parameters` with `initial_source_connection_id` = the Initial
  header's SCID (RFC 9000 §7.3).
- `append_quic_varint(...)` — RFC 9000 §16 variable-length integer.
- `build_crypto_frame(...)` — QUIC CRYPTO frame (type 0x06, offset 0).
- AES-GCM seal + AES-ECB header protection (RFC 9001 §5.4.3: sample 16 bytes at
  `pnOffset+4`, mask `byte0` low nibble + the 4 PN bytes).

**Public builder API (injectable randomness):**

```c
/* fill_random: production passes a get_random_bytes wrapper; tests pass a
 * deterministic source pinned to RFC 9001 Appendix A vectors so the whole
 * pipeline is byte-exact-checkable. The builder draws the random fields
 * (dcid 8, scid 8, pn 4, key_share pubkey 32, client_hello random 32) in a
 * single fixed order that the implementation documents and the byte-exact test
 * mirrors; the order matches the oracle's draw sequence so the same fixed
 * inputs reproduce the oracle's structure. */
typedef void (*qinit_rand_fn)(void *rctx, u8 *out, int n);

#define QINIT_DATAGRAM_LEN 1200  /* RFC 9000 §14.1 client-Initial minimum */

/* Build a QINIT_DATAGRAM_LEN-byte QUIC v1 Initial carrying a ClientHello with
 * `sni` into `buf` (must be >= QINIT_DATAGRAM_LEN). Returns 0 or -errno. */
int qinit_build(u8 *buf, const char *sni, qinit_rand_fn rand, void *rctx);
```

The fixed 1200-byte length keeps the QUIC `Length` field a 2-byte varint, exactly
as the oracle relies on. The builder performs **no heap allocation** — it writes
into the caller-provided `buf` and uses only fixed-size stack scratch — so it has
no lifetime to manage and is safe in any context (though it runs in process
context per §7).

### 5.2 Vendored crypto primitives — `src/crypto/`

Option B (vendored) was chosen over the kernel crypto API because: (a) qinit has
**no secret material** (keys are public-derivable by design), so there is no
constant-time/side-channel requirement and a simple table AES is safe; (b) it is
idiomatic to this module, which already vendors all of its crypto (zinc); (c) it
adds **no allocations/tfm lifetimes** to a path with a UAF history, unlike the
crypto-API approach; and (d) it has zero runtime `CONFIG_CRYPTO_*` dependency
across the 3.10–6.x kernel range. The cost — ~300 lines of primitives — is fully
retired by known-answer tests (§8).

New files under `src/crypto/`:

- `aes.c` / `aes.h` — AES-128 key expansion + single-block encrypt (the only AES
  operation qinit needs; used by both GCM and ECB header protection).
- `sha256.c` / `sha256.h` — SHA-256.

HMAC-SHA256, HKDF-Extract/Expand, and GHASH/GCM are thin layers built on the
above and live in `qinit.c` (they are short and qinit-specific). All added to
`src/crypto/Kbuild.include` (or `src/Kbuild`, matching the existing pattern).

### 5.3 Modifier-model extension — per-tag context (`ctx`)

The existing junk modifier signature carries no per-tag data:

```c
typedef void (*jp_modifier_func)(char *buf, int len, struct wg_peer *peer);
```

The `q`/`dns`/`stun`/`sip` tags need none (the proto is baked into the function
identity), but qinit must carry its **SNI string**. The model is extended with an
opaque `void *ctx` (chosen over a qinit-special-cased field so the mechanism
generalizes):

```c
typedef void (*jp_modifier_func)(char *buf, int len, struct wg_peer *peer,
				 void *ctx);

struct jp_tag      { ...; void *ctx; };   /* new field */
struct jp_modifier { ...; void *ctx; };   /* new field */
```

- The `qinit` parser `kstrdup`s the SNI into `tag->ctx`.
- **`ctx` uses copy semantics — the tag and the mod own independent
  `kstrdup`-ed copies.** This is mandatory, not a stylistic choice: there is **no
  "buf transfer" to ride alongside**. For modifier tags (`tag->func` set,
  `tag->pkt == NULL`, which is what `qinit` is), `jp_spec_setup` moves *nothing* —
  it `memcpy`s into `spec->pkt` only `if (tag->pkt)` (`src/junk.c:370-372`), and
  `mod->buf` points *into* `spec->pkt`, not into the tag. So `ctx` has no
  pre-existing analog and must be handled on its own terms.
- In the reverse-iteration loop, `mod->ctx = kstrdup(tag->ctx, GFP_KERNEL)` (a NULL
  return is `-ENOMEM` via the existing `error:` path). The tag keeps its own
  `tag->ctx`.
- **Why copy, not pointer-move:** `jp_spec_setup`'s `error:` label is the *common*
  exit — it runs `list_for_each_entry_safe(... jp_tag_free(tag) ... kfree(tag))`
  over **every** tag on the **success** path too (`src/junk.c:387-391`). A bare
  pointer-move (`mod->ctx = tag->ctx`) without NULLing `tag->ctx` would let
  `jp_tag_free` free a pointer the mod still holds → **double-free / UAF**. Copy
  semantics sidesteps this entirely; a move alternative would *require* an explicit
  `tag->ctx = NULL` after the move, which is more error-prone, so the spec mandates
  copy.
- `jp_tag_free` is extended to `kfree(tag->ctx)` (covers every error/success
  teardown of the tag list, including partial builds in `jp_parse_tags`).
- `jp_spec_free` frees each `mod->ctx` before `kfree(spec->mods)`.
- All **nine** existing modifiers (§9) gain the unused `void *ctx` parameter and
  ignore it.

**Lifetime note (CLAUDE.md UAF-sensitive path):** with copy semantics, `ctx` is a
heap string owned independently by the tag and by each mod; teardown is symmetric
(`jp_tag_free` frees the tag's copy, `jp_spec_free` frees the mods' copies) and no
pointer is ever shared across the tag/mod boundary. This is the single
highest-risk change in the spec and is called out for KASAN coverage in §8.

### 5.4 Tag wiring in `src/junk.c`

- New keyword `qinit` in `jp_parse_tags` (the `if (!strcmp(key, ...))` chain).
- `parse_qinit_tag(val, head)`: validates `val` is a non-empty SNI ≤ 255 bytes,
  `kstrdup`s it into `tag->ctx`, sets `tag->pkt_size = QINIT_DATAGRAM_LEN`,
  `tag->func = qinit_modifier`.
- `qinit_modifier(buf, len, peer, ctx)`: calls
  `qinit_build((u8 *)buf, (const char *)ctx, qinit_rand_getrandom, NULL)` where
  `qinit_rand_getrandom` wraps `get_random_bytes`. (qinit does not use the
  `jp_packet_counter` seed — every datagram is freshly random, matching Go.)
- **Exclusivity:** qinit produces a complete self-contained datagram;
  concatenating other tags in the same ispec would corrupt it. `jp_parse_tags`
  (or `jp_spec_setup`) rejects an ispec that mixes `qinit` with any other tag
  with `-EINVAL`.
- `QINIT_DATAGRAM_LEN` (1200) must satisfy the existing
  `pkt_size > MESSAGE_MAX_SIZE` guard in `jp_spec_setup`; verified during
  implementation (1200 is below the WireGuard message max).

## 6. Data flow (send path)

1. User sets `awg set <dev> i1=<qinit example.com>` → tools forwards the string
   via `WGDEVICE_A_I1` → `src/netlink.c` stores it in `wg->ispecs[0].desc`.
2. `jp_spec_setup` parses the desc, builds a 1200-byte `spec->pkt` template and a
   single `qinit_modifier` mod owning the SNI `ctx`.
3. On each handshake initiation, `wg_packet_send_handshake_initiation`
   (`src/send.c:28`) takes `spec->lock`, calls `jp_spec_applymods` →
   `qinit_modifier` rewrites the full 1200 bytes with a fresh QUIC Initial, then
   `wg_socket_send_buffer_to_peer` sends it. The shared `spec->pkt` buffer is
   mutated only under `spec->lock`.

## 7. Execution context

`wg_packet_send_handshake_initiation` runs in **process/workqueue context** — it
already calls `kzalloc(GFP_KERNEL)` and `mutex_lock`, both of which may sleep.
qinit therefore has no atomic-context constraint. (The builder is allocation-free
and context-agnostic regardless, so this is reassurance, not a dependency.)

## 8. Testing strategy

Correctness is proven by published standards, not by inspection. The vendored
primitives are pure and standalone, so they are tested in the existing
userspace harness (`tests/imitate/`, via `imitate_shim.h`) with the **same source**
that runs in-kernel, and as `src/selftest/` units in the debug build.

**Layer 1 — primitive known-answer tests (official vectors):**

| Primitive | Standard | Vectors |
| --- | --- | --- |
| AES-128 encrypt | FIPS-197 | Appendix B/C known-answer block |
| SHA-256 | FIPS-180-4 / NIST CAVP | short/long message KATs |
| HMAC-SHA256 | RFC 4231 | test cases 1–7 |
| HKDF-SHA256 | RFC 5869 | Appendix A.1–A.3 |
| AES-128-GCM | NIST CAVP `gcmEncrypt` | fixed key/IV/AAD/PT → CT+tag |

**Layer 2 — pipeline correctness, in three parts.** Note a whole-datagram match
against *RFC 9001 Appendix A* is **not** achievable (its worked example carries a
*different* ClientHello, so a different plaintext yields a different datagram) — so
the RFC anchors the **key schedule**, and a **Go-derived golden vector** anchors
the **whole datagram**:

1. **Key-schedule byte-exactness vs RFC 9001 Appendix A.1.** Feed the RFC's fixed
   DCID (`0x8394c8f03e515708`) to `derive_initial_keys` and assert
   `key`/`iv`/`hp` equal the RFC's documented values **byte-for-byte**. The
   legitimate "RFC worked example" anchor; transitively proves
   SHA-256 → HMAC → HKDF-Extract/Expand end-to-end. (Mirrors the oracle's
   `TestDeriveInitialKeysRFC9001`.)
2. **Whole-datagram byte-exact cross-impl golden vector (maximum guarantee).**
   The Go oracle is refactored (test-only, behavior-preserving) so the production
   builders accept an injected randomness source:
   - `buildQUICInitial` / `buildClientHello` gain an `io.Reader` parameter (e.g.
     `buildQUICInitialWithRand(r io.Reader, …)`); the existing exported entry
     points become thin wrappers passing `crypto/rand.Reader`, so **production
     output is byte-for-byte unchanged** (same source, same draw order).
   - With randomness pinned to a fixed stream, Go now emits a **deterministic**
     1200-byte datagram. Commit it as a frozen golden vector
     (`testdata/qinit_vector.bin` + the pinned random stream).
   - The **C test** feeds the *same* fixed stream to `qinit_rand_fn` and asserts
     `qinit_build` output equals the committed vector **byte-for-byte** — a true
     cross-implementation equality proof (identical ClientHello layout, extension
     order, cipher suites, transport params, AES-GCM seal, and header
     protection). This restores the Tiers 1–3 golden-vector oracle model under
     pinned randomness.
   - A **Go test** regenerates the datagram from the pinned stream and asserts it
     still equals the committed vector — guarding against oracle drift on the Go
     side. The C↔Go agreement is thus mediated by the committed vector; neither
     test needs the other's toolchain at runtime.

   *Draw-order precondition:* C and Go must consume the pinned stream in the same
   order and amounts (`dcid 8, scid 8, pn 4, key_share 32, ch_random 32`) — the
   review verified this order matches today; the byte-exact test makes any future
   divergence a hard failure.
3. **Whole datagram by self-decrypt round-trip.** Pin `qinit_rand_fn`, call
   `qinit_build`, then independently derive keys, AEAD-`Open`, strip header
   protection, and parse the ClientHello — asserting SNI / ALPN /
   `initial_source_connection_id` recover. Complements the golden vector: the
   vector proves *byte-identity to Go*; the round-trip proves *semantic validity*
   (a real decoder can read the SNI) and localizes failures to the seal/HP/framing
   stage. (Mirrors the oracle's `TestQInitRoundTrip`.)

**Layer 3 — independent cross-language interop:** the Layer-2 golden vector
already proves C↔Go byte-identity, so this layer adds decoders **we did not
write** to catch "C and Go agree but are *both* wrong about the spec":

1. An independent third-party QUIC stack (aioquic in Python, or quic-go) decrypts
   the C-generated Initial and recovers SNI/ALPN/transport-params.
2. `tshark -Y quic` dissection asserting the SNI field appears (automatable
   realism check — what a DPI box would see).

**Layer 4 — randomized property test:** generate N Initials with real random
inputs; assert every one decrypts, parses, and yields the correct SNI (catches
varint/length edge cases the fixed vectors miss).

**Cross-kernel:** `make test-qemu` runs the in-kernel selftests across kernel
versions for build/integration coverage; crypto math is already proven in
userspace and is kernel-version-independent (vendored, no `CONFIG_CRYPTO_*`).

**KASAN:** exercise the §5.3 `ctx` lifetime — set/reset/replace `I1`–`I5`
qinit tags repeatedly under `make module-debug` (subject to the pre-existing
`prandom_*` debug-build gap noted in the Tiers 1–3 work; if that blocks KASAN on
the target kernel, run the userspace harness under ASan as the interim memory
oracle).

## 9. Files touched

**Kernel repo (`amneziawg-proxy-linux-kernel-module`) — the feature:**

- `src/qinit.c`, `src/qinit.h` — new builder + QUIC/TLS framing + HKDF/GCM/HP.
- `src/crypto/aes.c`, `src/crypto/aes.h` — new (AES-128 encrypt).
- `src/crypto/sha256.c`, `src/crypto/sha256.h` — new (SHA-256).
- `src/Kbuild` (+ `src/crypto/Kbuild.include`) — add the new objects.
- `src/junk.h` — `jp_modifier_func` gains `void *ctx`; `jp_tag`/`jp_modifier`
  gain a `ctx` field.
- `src/junk.c` — `qinit` keyword + `parse_qinit_tag` + `qinit_modifier`; `ctx`
  copy (`kstrdup`) in `jp_spec_setup`; `ctx` free in `jp_spec_free` and
  `jp_tag_free`; qinit-exclusivity validation; the unused `ctx` param added to
  **all nine** existing modifiers (`pkt_counter`, `unix_time`, `random_byte`,
  `random_char`, `random_digit`, `imitate_{quic,dns,stun,sip}`).
- `src/selftest/` — primitive KATs + RFC 9001 App. A test.
- `tests/imitate/` — extend the userspace harness with the KATs, the byte-exact
  golden-vector test, and the interop/property tests; netns case for
  `i1=<qinit ...>`.
- `tests/imitate/testdata/qinit_vector.bin` (+ the pinned random stream) — the
  committed Go-derived golden vector (§8 Layer 2).

**Go repo (`amneziawg-go-proxy`) — test-only, behavior-preserving:**

- `device/obf_imitate_quic.go` — add `io.Reader` randomness parameter to
  `buildQUICInitial`/`buildClientHello`; existing entry points become wrappers
  passing `crypto/rand.Reader` (zero production-behavior change).
- `device/obf_imitate_quic_test.go` — pinned-stream deterministic build →
  regenerate/assert the committed golden vector (drift guard).

**Tools repo (`amneziawg-tools-proxy`):** untouched.

## 10. Implementation phasing

1. **Vendored primitives** (`aes.c`, `sha256.c`) + Layer-1 KATs green in the
   userspace harness. (No kernel behavior change.)
2. **Go oracle randomness refactor** (test-only, behavior-preserving) + pin a
   fixed stream + **commit the golden vector** (`qinit_vector.bin`); Go drift-guard
   test green. (No kernel work yet; this produces the byte-exact target.)
3. **`qinit.c` builder** (HKDF, key derivation, ClientHello, GCM seal, header
   protection) + Layer-2 green: RFC 9001 A.1 key-schedule byte-exactness, the
   **byte-exact match against the committed golden vector**, and the self-decrypt
   round-trip (SNI/ALPN/ISCID recover).
4. **Modifier-model `ctx` extension** (§5.3) + `qinit` tag parser/modifier in
   `junk.c` + exclusivity validation. KASAN/ASan on the `ctx` lifetime.
5. **Interop + property tests** (Layer 3: aioquic/tshark independent decode;
   Layer 4 randomized).
6. **netns end-to-end**: `i1=<qinit example.com>` against a vanilla peer — assert
   the peer drops it as junk and the tunnel still handshakes — plus KASAN under
   load.

## 11. Open risks

- **GHASH/GCM correctness** is the fiddliest vendored code; covered before any
  kernel wiring by the Layer-1 NIST `gcmEncrypt` vectors, the Layer-2 byte-exact
  golden vector (any GCM/GHASH divergence flips a ciphertext byte → vector
  mismatch), and the self-decrypt round-trip. The RFC 9001 A.1 key-schedule match
  anchors HKDF/HMAC/SHA-256, not GCM.
- **`ctx` lifetime** in the UAF-sensitive junk path (§5.3) — covered by KASAN/
  ASan in phase 3 and exercised by repeated tag set/reset.
- **`prandom_*` debug-build gap** (pre-existing, from Tiers 1–3) may block a true
  in-kernel KASAN run on 6.x/7.x; interim mitigation is ASan on the userspace
  harness. A `compat/` shim for `prandom_*` is out of scope for this spec but
  noted as the unblocking follow-up.
