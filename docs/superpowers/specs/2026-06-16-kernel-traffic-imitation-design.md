# Client-side traffic imitation — kernel module port (Tiers 1–3)

- **Status:** approved design, not built
- **Date:** 2026-06-16
- **Scope:** `amneziawg-proxy-linux-kernel-module` + `amneziawg-tools-proxy`
- **Source design sketch:** `~/Documents/.../awg3/Client-side traffic imitation for AmneziaWG.md`
- **Reference implementation (oracle):** `amneziawg-go-proxy` (`device/obf_imitate*.go`)

## 1. Goal

Port the client-side traffic-imitation feature already shipped in the Go fork to
the C kernel module, **Tiers 1–3 only**:

- **Tier 1 / Mechanism A** — shape the `S1`–`S4` padding prefix of real packets.
- **Tier 2 / Mechanism B** — shape standalone junk packets (`Jc`/`Jmin`/`Jmax`).
- **Tier 3 / Mechanism C** — shape I-packets (`I1`–`I5`) + a device-global
  protocol selector.

Tier 4 (`qinit` — fake QUIC Initial + SNI) is **deferred to a separate Phase 2
spec** because it requires the kernel crypto API (AES-128-GCM, HKDF-SHA256,
AES-ECB header protection) and is not byte-reproducible.

The feature is **sender-only, length-invariant, and interops with a vanilla
peer** — the receiver size-matches the padding and validates the magic header at
the padding offset without ever inspecting padding content
(`src/receive.c:38-67`). This is the "cosmetic" property that makes the port
safe.

## 2. Non-goals

- No receive-path changes.
- No layer-4 (size/timing) coverage — header shaping only.
- No Tier 4 / `qinit` in this phase.
- No change to existing `randObf` / random fallback behavior when the feature is
  off (`imitate_proto == IMITATE_NONE`).

## 3. Architecture

### 3.1 New translation unit: `src/imitate.c` + `src/imitate.h`

Mirrors Go's `device/obf_imitate.go`. Added to `src/Kbuild` `amneziawg-y` object
list. Pure byte-poking — **no floating point, no allocations in the writers**, so
it is safe in `GFP_ATOMIC`/softirq context (the `send.c:260` transport path).

**PRNG core (byte-exact with Go):**

- LCG step: `state = state * 1103515245u + 12345u` (u32 wraparound — glibc
  constants). Go: `obf_imitate.go:lcgStep`.
- `fnv1a_seed(payload, len)` — FNV-1a over first ≤64 bytes of the real payload;
  seeds QUIC/STUN/SIP. DNS ignores the seed. Go: `obf_imitate.go:fnv1aSeed`.
- `imitate_junk_seed(counter)` — FNV-1a over the 8-byte little-endian counter;
  decorrelates consecutive whole-datagram fills. Go:
  `obf_imitate.go:imitateJunkSeed`.

**Protocol writers** (same byte layout + small-pad fallbacks as Go — see the Go
file for the authoritative byte map; the golden vectors lock it):

- `write_quic_short` — RFC 9000 §17.3.1 1-RTT short header + LCG body.
- `write_dns` — RFC 6891 EDNS OPT response (≥32 bytes) / RFC 1035 NULL fallback
  (<32 bytes).
- `write_stun` — RFC 5389 Binding Success Response (XOR-MAPPED-ADDRESS +
  SOFTWARE).
- `write_sip` — RFC 3261 response header block.

**Public API:**

```c
enum imitate_proto { IMITATE_NONE, IMITATE_QUIC, IMITATE_DNS, IMITATE_STUN, IMITATE_SIP };

/* Seeds from buf[padding:]; writes exactly `padding` bytes at buf[0:padding].
   No-op if padding == 0 or padding >= total buffer length. */
void imitate_fill_prefix(u8 *buf, int total_len, int padding, enum imitate_proto proto);

/* Writes exactly `len` bytes from an explicit seed (junk / I-packets). */
void imitate_fill_whole(u8 *buf, int len, u32 seed, enum imitate_proto proto);

enum imitate_proto imitate_proto_parse(const char *s);  /* "none"/"quic"/"dns"/"stun"/"sip" */
const char *imitate_proto_name(enum imitate_proto p);
```

> **Byte-exactness contract:** `imitate_fill_prefix` and `imitate_fill_whole`
> must reproduce the Go output byte-for-byte for the same inputs. The LCG draw
> order per protocol (e.g. STUN: txn ×3 → port → addr → SOFTWARE chars) must
> match Go exactly. The golden vectors are the test of record.

### 3.2 Device state

Add to `struct wg_device` (`src/device.h`):

```c
enum imitate_proto imitate_proto;   /* device-global, default IMITATE_NONE */
atomic64_t imitate_junk_counter;    /* feeds imitate_junk_seed for mechanism B */
```

Default `IMITATE_NONE` preserves current random behavior — fully backward
compatible.

## 4. Wiring per mechanism

### 4.1 Mechanism A — S-padding

Sites (replace `get_random_bytes(...)`):

| Site | Packet | Note |
|---|---|---|
| `socket.c:201` | handshake init / response prefix | see §7 risk |
| `socket.c:227` | cookie / response prefix | see §7 risk |
| `send.c:260` | transport data prefix (`skb_push`) | softirq / `GFP_ATOMIC` |

New helper (in `imitate.c` or `device.c`):

```c
void wg_fill_padding(struct wg_device *wg, u8 *buf, int total_len, int padding) {
    if (wg->imitate_proto != IMITATE_NONE)
        imitate_fill_prefix(buf, total_len, padding, wg->imitate_proto);
    else
        get_random_bytes(buf, padding);   /* unchanged behavior */
}
```

### 4.2 Mechanism B — junk packets

Site: `send.c:70` (`get_random_bytes(buffer, junk_packet_size)`).

```c
void wg_fill_junk(struct wg_device *wg, u8 *buf, int len) {
    if (wg->imitate_proto != IMITATE_NONE) {
        u32 seed = imitate_junk_seed(atomic64_inc_return(&wg->imitate_junk_counter));
        imitate_fill_whole(buf, len, seed, wg->imitate_proto);
    } else {
        get_random_bytes(buf, len);   /* unchanged behavior */
    }
}
```

### 4.3 Mechanism C — I-packets (`junk.c`)

Add tags `<q N>`, `<dns N>`, `<stun N>`, `<sip N>`, each following the existing
`parse_rc_tag` / `random_char_modifier` pattern exactly — **no struct changes**
to `jp_tag` / `jp_modifier`. One modifier per protocol (proto baked into the
function, since the modifier signature carries no proto field):

```c
static void imitate_quic_modifier(char *buf, int len, struct wg_peer *peer) {
    u32 seed = imitate_junk_seed(atomic_read(&peer->jp_packet_counter));
    imitate_fill_whole(buf, len, seed, IMITATE_QUIC);
}
/* ...dns/stun/sip analogues... */

static int parse_q_tag(char *val, struct list_head *head) { /* like parse_r_tag, func = imitate_quic_modifier */ }
```

Register the four new keys in `jp_parse_tags` alongside `b/c/t/r/rc/rd`.

These ride the **existing** `I1`–`I5` netlink string attributes — **no new attr
and no tools change** for mechanism C.

## 5. Config plumbing (netlink + tools)

### 5.1 Kernel netlink (mechanisms A/B only)

- `src/uapi/wireguard.h`: add `WGDEVICE_A_IMITATE_PROTOCOL` to
  `enum wgdevice_attribute` (after `WGDEVICE_A_I5`).
- `src/netlink.c`:
  - add a `device_policy[]` entry (`NLA_NUL_STRING`);
  - parse in `wg_set_device` mirroring the H1–H4 string handling →
    `wg->imitate_proto = imitate_proto_parse(str)`;
  - emit in `wg_get_device_dump` via `nla_put_string` (name via
    `imitate_proto_name`).

### 5.2 tools fork `amneziawg-tools-proxy` (in scope)

The `ImitateProtocol` / `imitate_protocol` key already exists for the
userspace-daemon path (commit `fa52332`: `containers.h`, `config.c`,
`ipc-uapi.h`, `showconf.c`). This work adds the **kernel netlink path**:

- `src/ipc-linux.h`:
  - `kernel_set_device`: after the `I1`–`I5` block, if
    `WGDEVICE_HAS_IMITATE_PROTOCOL`, `nla_put_string(WGDEVICE_A_IMITATE_PROTOCOL,
    dev->imitate_protocol)`.
  - `parse_device` (get path): handle `WGDEVICE_A_IMITATE_PROTOCOL` →
    `dev->imitate_protocol` + set the flag.
- `src/uapi/wireguard.h` (tools copy): add the matching
  `WGDEVICE_A_IMITATE_PROTOCOL` enum so both sides agree on the attribute number.

> **Attribute-number contract:** the enum value of `WGDEVICE_A_IMITATE_PROTOCOL`
> must be identical in the kernel and tools `wireguard.h` copies.

## 6. Testing

### 6.1 Userspace golden harness (primary, fast loop)

- Location: `tests/imitate/`.
- Compile `src/imitate.c` standalone in userspace behind a thin shim header that
  provides `u8/u32/u64`, `htons`/`htonl`, and a stubbed `get_random_bytes`
  (unused by the deterministic writers).
- Parse `amneziawg-go-proxy/device/testdata/imitate_vectors.txt` (format:
  `<proto> <pad> <payload_hex> <output_hex>`); for each line call
  `imitate_fill_prefix` and assert byte-exact equality.
- Add `make -C tests/imitate test` (or a top-level `make imitate-test`).
- A failing vector is a hard error — this is the byte-exactness gate.

### 6.2 netns interop anchor

- Two `ip netns`, veth pair, port `tests/netns.sh` style harness:
  1. **patched-kernel sender ↔ vanilla peer** — tunnel comes up, `ping`/`iperf`
     pass → proves the cosmetic + interop claim.
  2. patched ↔ patched.
  3. bonus: **patched-kernel ↔ vanilla `amneziawg-go`** cross-impl.
- Run with `imitate_protocol=quic` and an `I1=<q 600>` decoy.

### 6.3 Realism spot-check

- `tcpdump` the veth → Wireshark / QUIC dissector confirms classification as the
  selected protocol and that it consumes exactly `padding` bytes, leaving
  `[magic header + ciphertext]` opaque.

### 6.4 Fuzz / edge

- Tiny `s` values (`padding` < protocol header size) → confirm fallback, no
  length drift, no oops. Mirror the Go `obf_imitate_whole_test.go` tiny-size
  cases.

## 7. Known risks

1. **Payload presence at fill time (mechanism A).** In `socket.c` handshake
   paths the junk prefix may be filled *before* the real message bytes are
   copied in; Go fills *after* (`copy(buf[padding:], packet)` then
   `fillPadding`). The unit harness stays byte-exact regardless (it tests the
   function with payload present). For runtime, each `socket.c` site must either
   be reordered to fill after the message is placed, or accept buffer-state
   seeding (still protocol-valid + vanilla-interop, only decorrelation differs).
   The implementation plan resolves this per-site and documents the choice.
2. **Hot-path discipline.** `send.c:260` runs per-packet in softirq. The writers
   must stay allocation-free and FP-free (they are). Verify with
   `make module-debug` (KASAN) under load.
3. **`junk.c` memory safety.** This file had recent use-after-free / corruption
   fixes; new tags must follow the exact alloc/lifetime pattern of the existing
   parsers and be exercised under KASAN.
4. **Attribute-number drift** between kernel and tools `wireguard.h` — covered by
   the §5.2 contract; add a comment in both files.
5. **Endianness.** Writers use explicit `htons`/`htonl` for protocol fields and
   raw LCG bytes for filler; golden vectors were generated little-endian-host —
   the harness must run on the same byte order assumptions the writers encode
   (writers are explicit, so this is safe; note it in the harness).

## 8. Deliverables / file map

Kernel (`amneziawg-proxy-linux-kernel-module`):

- `src/imitate.c`, `src/imitate.h` — new.
- `src/Kbuild` — add `imitate.o`.
- `src/device.h` — `imitate_proto`, `imitate_junk_counter`.
- `src/socket.c` (×2), `src/send.c` (×2) — A + B call sites.
- `src/junk.c` — four new tags + modifiers.
- `src/netlink.c`, `src/uapi/wireguard.h` — `WGDEVICE_A_IMITATE_PROTOCOL`.
- `tests/imitate/` — golden harness; netns additions.

tools (`amneziawg-tools-proxy`):

- `src/ipc-linux.h` — send/parse `imitate_protocol` over netlink.
- `src/uapi/wireguard.h` — matching attribute enum.

## 9. Implementation phasing

1. `imitate.c/.h` + userspace golden harness → green against vectors. (No kernel
   behavior change yet.)
2. Mechanism A (3 sites) + `WGDEVICE_A_IMITATE_PROTOCOL` + tools wiring → netns
   interop with `imitate_protocol=quic`.
3. Mechanism B (`send.c:70`).
4. Mechanism C (`junk.c` tags) → netns with `I1=<q 600>`.
5. Realism + fuzz pass; KASAN under load.
6. (Later, separate spec) Tier 4 `qinit`.
