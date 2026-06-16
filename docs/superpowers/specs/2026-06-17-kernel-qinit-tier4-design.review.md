# Review — Kernel `qinit` Tier 4 design (fake QUIC Initial + SNI)

- **Reviews:** `2026-06-17-kernel-qinit-tier4-design.md`
- **Reviewer:** Claude (Opus 4.8), cross-checked against the Go oracle and the live kernel tree
- **Date:** 2026-06-17
- **Verdict:** **Approve with changes.** The architecture is right, the
  no-ABI-change framing holds, the crypto-primitive choices are correct, and the
  send-path integration is accurately described. **Two issues must be fixed before
  build:** the §8 Layer-2 test target is not achievable as written (**F1**), and
  the §5.3 `ctx` lifetime is under-specified in a way that invites a double-free in
  the UAF-sensitive junk path (**F2**).

---

## What I verified (evidence)

| Spec claim | Result | Evidence |
|---|---|---|
| Baseline: Tiers 1–3 merged (PR #1), `q/dns/stun/sip` tags exist | ✅ | `git log`: merge `c0d7c1a`; `imitate_{quic,dns,stun,sip}_modifier` at `junk.c:185-211`; `imitate.c`/`imitate.h` present |
| Send path: `wg_packet_send_handshake_initiation` takes `spec->lock` → `jp_spec_applymods` → `wg_socket_send_buffer_to_peer` | ✅ exact | `send.c:28` fn; `send.c:52-56` lock/apply/send/unlock; mutation under `spec->lock` confirmed |
| §7 process/workqueue (sleepable) context | ✅ | same fn calls `kzalloc(GFP_KERNEL)` (`send.c:65`) and `mutex_lock` — proves sleepable; AES/SHA work is safe here |
| Draw order `dcid8, scid8, pn4, key_share32, ch_random32` matches oracle | ✅ exact | `buildQUICInitial` draws dcid/scid/pn (`obf_imitate_quic.go:195-197`), then `buildClientHello` draws key_share pub (`:143`) then ClientHello random (`:162`) |
| AES single-block-encrypt is the only AES op needed | ✅ | sender only *seals* (GCM-CTR keystream + GHASH `H=E(0)` + ECB header-protection mask) — no AES-decrypt; no `Open` in kernel |
| `pkt_size > MESSAGE_MAX_SIZE` guard accommodates 1200 | ✅ trivially | `messages.h:132` `MESSAGE_MAX_SIZE = 65535` |
| No ABI / no tools change (qinit rides opaque `I1`–`I5`) | ✅ | confirmed in the Tiers 1–3 review: tools store `i1`–`i5` via `parse_awg_string`, no tag interpretation |
| `qinit` skips `jp_packet_counter` (fresh random each call) | ✅ matches oracle | Go `buildQUICInitial` uses `crypto/rand` per call, no counter |
| HKDF-Expand-Label `"tls13 "`+zero-context; Extract(salt=initial_salt, ikm=dcid); labels `client in`/`quic key`/`quic iv`/`quic hp` | ✅ matches oracle | `obf_imitate_quic.go:26-55` |

Architecture strengths worth keeping: isolating crypto in `src/qinit.c` + `src/crypto/`
**out of** `junk.c`; the vendored-primitive rationale (no secrets ⇒ no constant-time
requirement, no `CONFIG_CRYPTO_*` dep, no tfm lifetimes on a UAF-prone path); and the
injectable-randomness builder API. All sound.

---

## Findings

### F1 — §8 Layer-2 "byte-exact vs RFC 9001 Appendix A whole datagram" is not achievable *(Medium-High)*

§8 Layer 2 says: *"assert `qinit_build` output equals the RFC's documented
protected client Initial **byte-for-byte**."* This cannot hold. RFC 9001
Appendix A is a worked example over a **specific, real ClientHello** (its own
extension set and CRYPTO-frame bytes). `qinit_build` emits a **different**
ClientHello (`server_name` + `supported_versions` + `supported_groups` +
`key_share` + `signature_algorithms` + ALPN `h3` + `quic_transport_parameters`,
in this fork's layout). Different plaintext ⇒ different ciphertext ⇒ the whole
1200-byte datagram will **never** equal the RFC's example.

Crucially, the Go oracle itself does **not** make this claim. Its test suite does:
- `TestDeriveInitialKeysRFC9001` — byte-exact **key/iv/hp only**, for the RFC's
  fixed DCID `0x8394c8f03e515708` (`obf_imitate_quic_test.go:22-37`). This is the
  *key schedule*, not the datagram.
- `TestQInitRoundTrip` — **self-decrypt**: build → AEAD `Open` → parse, assert
  SNI == `example.com` (`:148`).
- `TestQInitConsecutiveDiffer` — two builds differ (`:176`).

**Fix — scope the byte-exactness correctly:**
1. Keep RFC 9001 **A.1 byte-exactness for the key schedule** (DCID → key/iv/hp) —
   that is the legitimate "RFC worked example" anchor, and it transitively proves
   HKDF/HMAC/SHA-256 end-to-end.
2. Prove the **whole datagram by self-decrypt round-trip** (pin `qinit_rand_fn`,
   then derive keys + `Open` + parse and assert SNI/ALPN/ISCID) — this is the
   oracle's method and what your §2 table already calls "cross-impl decrypt."
3. If you want a frozen whole-datagram **regression** anchor, pin the randomness
   and commit `qinit_build`'s output once as a golden vector (catches drift, not
   correctness). A true cross-impl byte-exact match against Go is possible **only
   if** the Go oracle is first refactored to accept injected randomness (today its
   `rand.Read` calls are hardcoded) — note that cost if you go that route.

The standalone GCM/AES/SHA known-answer tests (Layer 1) stay as-is and are the
right home for "primitive equals NIST/RFC vector byte-for-byte."

### F2 — §5.3 `ctx` lifetime invites a double-free in the cleanup tail *(Medium-High; the highest-risk change)*

The spec says `jp_spec_setup` *"transfers `ctx` ownership tag→mod alongside the
existing `buf` transfer."* Two problems make this dangerous as written:

1. **There is no "existing `buf` transfer" to ride alongside.** For modifier tags
   (which `qinit` is — `tag->func` set, `tag->pkt == NULL`), `jp_spec_setup` does
   **not** move anything: it `memcpy`s `tag->pkt` into a fresh `spec->pkt` only
   `if (tag->pkt)` (`junk.c:370-372`), and `mod->buf` points into `spec->pkt`, not
   into the tag. So the literal-bytes path is **copy-then-free-original**, and the
   modifier path copies *nothing*. `ctx` (the SNI heap string) has **no existing
   analog** — it must be handled on its own terms.

2. **The cleanup tail frees every tag unconditionally, on success and error.**
   `jp_spec_setup`'s `error:` label is the common exit; it runs
   `list_for_each_entry_safe(... jp_tag_free(tag); ... kfree(tag))` for **all**
   tags even on the success path (`junk.c:387-391`). So if the reverse loop
   "transfers" `ctx` by **pointer move** (`mod->ctx = tag->ctx`) without NULLing
   `tag->ctx`, `jp_tag_free` then frees the same pointer `mod->ctx` still holds →
   **double-free / UAF** the moment the mod is used or `jp_spec_free` runs. This is
   exactly the bug class CLAUDE.md flags for this path.

**Fix — prescribe one explicit discipline, not "alongside `buf`":**
- **Preferred (copy semantics, symmetric with how `pkt` literals are handled):**
  in the reverse loop, `mod->ctx = kstrdup(tag->ctx, GFP_KERNEL)` (handle NULL
  alloc as `-ENOMEM` via the existing `error:` path); extend `jp_tag_free` to
  `kfree(tag->ctx)`; extend `jp_spec_free` to `kfree(mod->ctx)` for each mod before
  `kfree(spec->mods)`. No NULLing needed; tag and mod own independent copies.
- **Alternative (move semantics):** `mod->ctx = tag->ctx; tag->ctx = NULL;` — then
  the unconditional `jp_tag_free` is a no-op on the moved string. If you choose
  this, the spec must state the NULL-out explicitly; omitting it is the bug above.

Either is fine, but the spec must pick one and spell out the NULL/copy invariant,
because the current "transfer alongside buf" wording maps onto a `memcpy`-and-free
pattern that does **not** generalize to a moved pointer.

### F3 — §9 "five existing modifiers" is an undercount *(Low)*

Adding `void *ctx` to `jp_modifier_func` touches **nine** existing modifiers, not
five: `pkt_counter_modifier`, `unix_time_modifier`, `random_byte_modifier`,
`random_char_modifier`, `random_digit_modifier`, and the four
`imitate_{quic,dns,stun,sip}_modifier` (`junk.c:59,82,105,130,160,185,192,199,206`).
A miss is a compile error, so it self-corrects — but the file map should say "all
existing modifiers (9)" so the signature sweep is complete and reviewers can count.

### F4 — Note the HKDF-Extract argument order explicitly *(Low / affirm)*

`derive_initial_keys` must call `HKDF-Extract` with **salt as the HMAC key** and
`dcid` as IKM (`initial_secret = Extract(salt=quic_v1_initial_salt, ikm=dcid)`).
Hand-rolled HKDF commonly swaps these. It is covered by the RFC 5869 KATs **and**
the RFC 9001 A.1 key vector (which only passes if the order is right), but a
one-line note in §5.1/§5.2 will save an implementer a confusing debug session.

---

## Bottom line

The design is accurate where it touches real code and ready to drive
implementation once **F1** (replace the impossible RFC whole-datagram byte-match
with key-schedule KAT + self-decrypt round-trip) and **F2** (pin down `ctx`
copy-or-move semantics against the unconditional cleanup tail) are folded in. F3/F4
are doc tightening. Suggested phasing fit: F1 lands in phase 2 (the byte-exact
test gate), F2 in phase 3 (the `ctx` extension), exactly where the spec already
puts the corresponding work.
