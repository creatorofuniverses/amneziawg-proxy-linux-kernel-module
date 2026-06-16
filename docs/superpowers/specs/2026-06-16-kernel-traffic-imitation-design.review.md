# Review — Kernel traffic-imitation design (Tiers 1–3)

- **Reviews:** `2026-06-16-kernel-traffic-imitation-design.md`
- **Reviewer:** Claude (Opus 4.8), cross-checked against the live source of all three repos
- **Date:** 2026-06-16
- **Verdict:** **Approve with changes.** The design is sound, the call sites are
  real, and the cosmetic/interop reasoning is correct. Fix **F1** and **F2**
  before (or as the first step of) implementation; the rest are doc/clarity nits.

---

## What I verified (evidence)

Every concrete claim in the spec was checked against the actual trees, not taken
on faith:

| Spec claim | Result | Evidence |
|---|---|---|
| A-sites `socket.c:201`, `socket.c:227`, `send.c:260` | ✅ exact | `get_random_bytes(junk, junk_size)` ×2; `get_random_bytes(skb_push(skb, junk_size), junk_size)` |
| B-site `send.c:70` | ✅ exact | `get_random_bytes(buffer, junk_packet_size)` |
| C-site `junk.c:105` (`random_byte_modifier`) | ✅ exact | swap target confirmed |
| Cosmetic property `receive.c:38-67` | ✅ holds | `prepare_awg_message`: size-match → `skb_pull` → `mh_validate` for all four message types; padding content never inspected |
| `jp_modifier_func` sig matches proposed modifiers | ✅ | `typedef void(*jp_modifier_func)(char*, int, struct wg_peer*)` (`junk.h:9`) — the proposed `imitate_quic_modifier(char*, int, struct wg_peer*)` is signature-compatible |
| `peer->jp_packet_counter` exists, `atomic_read`-able | ✅ | used at `junk.c:59` |
| `parse_q_tag` can clone `parse_r_tag`/`parse_rc_tag` | ✅ | identical `kzalloc`→`pkt_size`/`func`→`list_add` shape |
| "No tools change for mechanism C" | ✅ | tools store `i1`–`i5` as opaque strings via `parse_awg_string` (`config.c:581`), no tag-letter validation — `<q 600>` passes straight through |
| Tools `imitate_protocol` already wired (commit `fa52332`) | ✅ | `containers.h:133` field, `:100` flag `1U<<21`, `config.c:600/912`, `ipc-uapi.h:87/318`, `showconf.c:81` |
| LCG `1103515245`/`12345`, FNV-1a `0x811c9dc5`/`0x01000193` | ✅ match Go | `device/obf_imitate.go:63-89` |
| Netlink enum tail (add `WGDEVICE_A_IMITATE_PROTOCOL` after `_A_I5`, before `__WGDEVICE_A_LAST`) | ✅ correct | `uapi/wireguard.h:205-206` |
| Vector file format `<proto> <pad> <payload_hex> <output_hex>` | ✅ | 128 lines, 32 per proto |

Strengths worth keeping: reusing the Go `imitate_vectors.txt` as the cross-impl
oracle is the right move; the pure-writer / seed-at-call-site split keeps the
writers allocation-free (softirq-safe) **and** userspace-compilable; the Tier-4
deferral (needs kernel crypto API, not byte-reproducible) is well-justified.

---

## Findings

### F1 — Golden harness only locks Mechanism A; B and C are not gated *(Medium)*

§6.1 says "for each line call `imitate_fill_prefix`." But the vector file
**only contains prefix cases**, and prefix ≠ whole in the Go oracle:

- Prefix path → `imitateFill` → `writeDNS` (TXID seeded **from payload**).
- Whole path → `imitateFillWhole` → `writeDNSWhole` (TXID seeded **from the
  injected `seed`**) — a *distinct* code path (`obf_imitate.go:110,129`).
- Mechanisms B and C also depend on `imitate_junk_seed` (counter → FNV-1a → u32),
  which **no prefix vector exercises**.

Consequence: as written, the byte-exactness gate proves `imitate_fill_prefix`
(Mechanism A) only. The kernel's `imitate_fill_whole` for **DNS** and the
**`imitate_junk_seed`** derivation would ship with no cross-impl oracle. (QUIC/
STUN/SIP whole are *transitively* close because they reuse the same writers, but
the seed→TXID DNS divergence and the counter-hash are genuinely untested.)

**Fix:** extend `imitate_vectors.txt` + `tools/imitate-vectors/regen.sh` with
whole-fill rows, e.g. `<proto> whole <len> <seed_hex> <output_hex>`, and have the
C harness branch to `imitate_fill_whole` for those. Cheap, and it closes the gate
for the two tiers the spec is actually adding.

### F2 — "Accept buffer-state seeding" at `socket.c` means hashing uninitialized skb memory *(Medium)*

Confirmed: both `socket.c` A-sites fill the junk **before** the payload exists —
`junk = skb_put(...); get_random_bytes(junk, junk_size); skb_put_data(skb, buffer, len);`
(`socket.c:200-202`). So `imitate_fill_prefix`'s "seed from `buf[padding:]`" would
read **uninitialized** skb bytes at these sites.

Risk #1 already flags the ordering, but offers "or accept buffer-state seeding" as
an acceptable alternative. In kernel context that alternative is **not** benign:
hashing uninitialized memory is a KMSAN use-of-uninitialized-value report and a
(theoretical) info-leak channel — even though the *output* is cosmetic.

**Fix:** drop the uninit-seed option; **always reorder**. The reorder is trivial
because the regions are contiguous from the `junk` pointer: do `skb_put`(junk) →
`skb_put_data`(buffer) → **then** `imitate_fill_prefix(junk, junk_size + len, junk_size, proto)`.
After both puts, `junk[junk_size:]` is the real message, so the seed is valid and
the fill stays in the reserved prefix. Make this the prescribed pattern for both
`socket.c` sites in §4.1/§7.

### F3 — `send.c:260` seeds from *plaintext, pre-encryption* — note it, not a blocker *(Low)*

At `send.c:260` the junk is `skb_push`ed in front of the data header **before**
encryption, so `buf[padding:]` is the plaintext `message_data` header + plaintext.
Seeding off low-entropy header bytes (type / key_idx / counter) is fine for
cosmetics and the per-packet `counter` gives variation — but the spec should state
that runtime decorrelation here rides on the counter field, and that Go-vs-kernel
runtime bytes will differ (only the *harness* is byte-exact, which the spec
already says). No change needed beyond a one-line note.

### F4 — Mechanism C is independent of the device-global selector — say so *(Low)*

§1 frames Tier 3 as "Mechanism C … **+** a device-global protocol selector,"
which reads as if `<q>`/`<dns>` I-packets are governed by `imitate_proto`. They
are not: the proposed `imitate_quic_modifier` bakes `IMITATE_QUIC` in (the
`jp_modifier_func` signature carries no device/proto), so an `I1=<q 600>` decoy is
QUIC-shaped **even when `imitate_protocol=none`**. This matches the Go model
(`i1=<q 600>` names the proto in the chain) and is correct — just make §1/§4.3
explicit: **`imitate_proto` governs A and B only; C is per-tag.**

### F5 — Path/citation nits *(Low)*

- §5.2 and §8 cite the tools header as `src/uapi/wireguard.h`. Actual path is
  `src/uapi/linux/linux/wireguard.h`. Fix so the "attribute-number contract" comment
  lands in the right file.
- The `receive.c` transport case matches with `>=` (`skb->len >= junk_size +
  MESSAGE_TRANSPORT_SIZE`), not `==` like the three handshake cases. The cosmetic
  claim still holds; worth a half-sentence so an implementer isn't surprised.

---

## Bottom line

The spec is accurate where it counts and ready to drive implementation once **F1**
(add whole-fill vectors) and **F2** (mandate reorder, drop uninit-seed) are folded
in. Suggested phasing tweak: do F1 as part of phasing step 1 (the harness lands
before any kernel change anyway), and bake F2 into step 2's `socket.c` work.
