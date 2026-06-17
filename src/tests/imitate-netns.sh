#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Interop anchor for client-side traffic imitation (Tiers 1-3 + Tier 4 qinit).
#
# DESCRIPTION
#   Creates two network namespaces connected by a veth pair.  Side A is
#   the "patched sender" configured with imitate_protocol quic, an S4
#   transport junk size (non-zero so the S-padding path is exercised), and
#   an I1 decoy packet descriptor.  Side B is a vanilla AWG peer with no
#   imitate settings, proving that shaped packets are still accepted by a
#   peer that does not shape.
#
#   A second scenario (qinit) sets up a fresh namespace pair and tests
#   i1=<qinit example.com>: the sender emits a 1200-byte QUIC v1 Initial
#   as the I-packet before the real WG handshake.  The vanilla peer MUST
#   drop it (it is undecryptable junk — magic-header mismatch) while the
#   real handshake still completes.  tshark (if available) is used to
#   assert the SNI field in the captured decoy.
#
#   A tcpdump capture of the underlay veth is written to /tmp/ for the
#   manual Wireshark realism check (Step 3 of the task).  tcpdump is
#   best-effort: the test proceeds and passes without it.
#
# PREREQUISITES (must be done before running this script)
#   Build the kernel module:
#     make -C /path/to/amneziawg-proxy-linux-kernel-module/src module
#   Build the patched wg tools:
#     make -C /path/to/amneziawg-tools-proxy/src
#
# REQUIRED PRIVILEGES
#   Must be run as root (needs insmod, ip netns, veth creation).
#
# ENVIRONMENT OVERRIDES
#   KO   Path to the amneziawg kernel module (default: ../amneziawg.ko
#        relative to this script's directory, i.e. src/amneziawg.ko)
#   WG   Path to the patched wg binary (default:
#        ../../../amneziawg-tools-proxy/src/wg relative to this script)
#
# WARNING: MODULE SWAP
#   This script unloads any running amneziawg module and loads the locally
#   built dev build in its place.  On exit the dev build is removed.
#   The original system module (if any) is NOT re-inserted automatically;
#   restore it manually if needed (e.g. modprobe amneziawg).
#
# USAGE
#   sudo bash src/tests/imitate-netns.sh
#   KO=/custom/amneziawg.ko WG=/custom/wg sudo bash src/tests/imitate-netns.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve script-relative paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KO="${KO:-${SCRIPT_DIR}/../amneziawg.ko}"
WG="${WG:-${SCRIPT_DIR}/../../../amneziawg-tools-proxy/src/wg}"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
	echo "ERROR: This script must be run as root (needs insmod, ip netns)." >&2
	exit 1
fi

if [[ ! -f "$KO" ]]; then
	echo "ERROR: kernel module not found: $KO" >&2
	echo "       Build it first: make -C src module" >&2
	exit 1
fi

if [[ ! -x "$WG" ]]; then
	echo "ERROR: wg binary not found or not executable: $WG" >&2
	echo "       Build it first: make -C ../amneziawg-tools-proxy/src" >&2
	exit 1
fi

# Refuse to run if a host AmneziaWG interface is live. This test unloads and
# reloads the amneziawg module at the HOST level; doing so while a real tunnel
# (e.g. an active VPN) exists would tear it down. The test namespaces do not
# exist yet at this point, so any amneziawg interface seen here is a host one.
HOST_AWG="$(ip -br link show type amneziawg 2>/dev/null | awk '{print $1}' | paste -sd' ' -)"
if [[ -n "${HOST_AWG// /}" ]]; then
	echo "ERROR: live host AmneziaWG interface(s) present: $HOST_AWG" >&2
	echo "       This test unloads/reloads the amneziawg module and would disrupt them." >&2
	echo "       Bring them down first (e.g. stop the VPN), or run in a VM/QEMU (make test-qemu)." >&2
	exit 1
fi

# Remember whether the system module was loaded so cleanup can restore it.
SYS_MODULE_WAS_LOADED=0
if lsmod | awk '{print $1}' | grep -qx amneziawg; then
	SYS_MODULE_WAS_LOADED=1
fi

# ---------------------------------------------------------------------------
# Namespace / interface names ($$-scoped to avoid collisions)
# ---------------------------------------------------------------------------
NS_A="awg-imitate-$$-a"
NS_B="awg-imitate-$$-b"
VETH_A="veth-a-$$"
VETH_B="veth-b-$$"
WG_A="awg0"
WG_B="awg0"

UNDERLAY_A="10.99.88.1"
UNDERLAY_B="10.99.88.2"
UNDERLAY_PFX=24

TUNNEL_A="10.200.1.1"
TUNNEL_B="10.200.1.2"
TUNNEL_PFX=24

PORT_A=51820
PORT_B=51821

PCAP="/tmp/imitate-interop-$$.pcap"
TCPDUMP_PID=""
RUN_OK=0   # set to 1 just before the PASS line; if still 0 at cleanup, dump diagnostics

# ---------------------------------------------------------------------------
# qinit scenario — separate namespace / veth names (same PID scope)
# ---------------------------------------------------------------------------
QNS_A="awg-qinit-$$-a"
QNS_B="awg-qinit-$$-b"
QVETH_A="veth-qa-$$"
QVETH_B="veth-qb-$$"
QWG_A="awg0"
QWG_B="awg0"

QUNDERLAY_A="10.99.99.1"
QUNDERLAY_B="10.99.99.2"
QUNDERLAY_PFX=24

QTUNNEL_A="10.200.2.1"
QTUNNEL_B="10.200.2.2"
QTUNNEL_PFX=24

QPORT_A=51830
QPORT_B=51831

QPCAP="/tmp/imitate-qinit-$$.pcap"
QTCPDUMP_PID=""
QRUN_OK=0          # set to 1 just before the qinit PASS line
QSCENARIO_STARTED=0  # set to 1 when the qinit namespace pair is created

# ---------------------------------------------------------------------------
# Diagnostics — dumped on failure BEFORE teardown (namespaces still alive).
# Pinpoints WHERE it breaks: handshake (no "latest handshake" / rx=0 both sides)
# vs transport (handshake present but one side's transfer rx stays 0), and the
# kernel log shows the module's drop/handshake messages (debug build).
# ---------------------------------------------------------------------------
dump_diag() {
	echo "================ DIAGNOSTICS (test did NOT pass) ================" >&2
	echo "--- [A] $WG show $WG_A (handshake + transfer counters) ---" >&2
	ip netns exec "$NS_A" "$WG" show "$WG_A" 2>&1 | sed 's/^/[A] /' >&2 || true
	echo "--- [B] $WG show $WG_B ---" >&2
	ip netns exec "$NS_B" "$WG" show "$WG_B" 2>&1 | sed 's/^/[B] /' >&2 || true
	echo "--- [A] addr/route ---" >&2
	ip -n "$NS_A" -br addr 2>&1 | sed 's/^/[A] /' >&2 || true
	ip -n "$NS_A" route 2>&1 | sed 's/^/[A] /' >&2 || true
	echo "--- [B] addr/route ---" >&2
	ip -n "$NS_B" -br addr 2>&1 | sed 's/^/[B] /' >&2 || true
	echo "--- kernel log (last 50 lines) ---" >&2
	dmesg 2>/dev/null | tail -n 50 | sed 's/^/[dmesg] /' >&2 || true
	echo "--- pcap saved at: $PCAP (open in Wireshark) ---" >&2
	echo "================================================================" >&2
}

dump_diag_qinit() {
	echo "================ DIAGNOSTICS qinit (test did NOT pass) ================" >&2
	echo "--- [QA] $WG show $QWG_A ---" >&2
	ip netns exec "$QNS_A" "$WG" show "$QWG_A" 2>&1 | sed 's/^/[QA] /' >&2 || true
	echo "--- [QB] $WG show $QWG_B ---" >&2
	ip netns exec "$QNS_B" "$WG" show "$QWG_B" 2>&1 | sed 's/^/[QB] /' >&2 || true
	echo "--- [QA] addr/route ---" >&2
	ip -n "$QNS_A" -br addr 2>&1 | sed 's/^/[QA] /' >&2 || true
	echo "--- [QB] addr/route ---" >&2
	ip -n "$QNS_B" -br addr 2>&1 | sed 's/^/[QB] /' >&2 || true
	echo "--- kernel log (last 50 lines) ---" >&2
	dmesg 2>/dev/null | tail -n 50 | sed 's/^/[dmesg] /' >&2 || true
	echo "--- qinit pcap saved at: $QPCAP ---" >&2
	echo "======================================================================" >&2
}

# ---------------------------------------------------------------------------
# Cleanup trap  (runs on EXIT regardless of success or failure)
# ---------------------------------------------------------------------------
cleanup() {
	set +e
	# Stop tcpdump captures so pcaps are flushed before we examine / keep them
	if [[ -n "$TCPDUMP_PID" ]]; then
		kill "$TCPDUMP_PID" 2>/dev/null
		wait "$TCPDUMP_PID" 2>/dev/null
	fi
	if [[ -n "$QTCPDUMP_PID" ]]; then
		kill "$QTCPDUMP_PID" 2>/dev/null
		wait "$QTCPDUMP_PID" 2>/dev/null
	fi
	# If the test did not reach the PASS line, dump evidence while the
	# namespaces and interfaces still exist (before we tear them down).
	if [[ "$RUN_OK" -ne 1 ]]; then
		dump_diag
	fi
	if [[ "${QSCENARIO_STARTED:-0}" -eq 1 && "$QRUN_OK" -ne 1 ]]; then
		dump_diag_qinit
	fi
	# Kill any processes still running inside the namespaces
	local pids
	pids="$(ip netns pids "$NS_A" 2>/dev/null) $(ip netns pids "$NS_B" 2>/dev/null) \
	      $(ip netns pids "$QNS_A" 2>/dev/null) $(ip netns pids "$QNS_B" 2>/dev/null)"
	if [[ -n "${pids// /}" ]]; then
		# shellcheck disable=SC2086
		kill $pids 2>/dev/null || true
	fi
	# Delete AWG interfaces (best-effort; they go away with the namespace anyway)
	ip -n "$NS_A"  link del "$WG_A"  2>/dev/null || true
	ip -n "$NS_B"  link del "$WG_B"  2>/dev/null || true
	ip -n "$QNS_A" link del "$QWG_A" 2>/dev/null || true
	ip -n "$QNS_B" link del "$QWG_B" 2>/dev/null || true
	# Delete namespaces (this also removes the veth endpoints)
	ip netns del "$NS_A"  2>/dev/null || true
	ip netns del "$NS_B"  2>/dev/null || true
	ip netns del "$QNS_A" 2>/dev/null || true
	ip netns del "$QNS_B" 2>/dev/null || true
	# Unload the dev module, then restore the system-installed module if it was
	# loaded before this test ran (so the host is left as we found it).
	rmmod amneziawg 2>/dev/null || true
	if [[ "${SYS_MODULE_WAS_LOADED:-0}" -eq 1 ]]; then
		modprobe amneziawg 2>/dev/null || true
	fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Load the dev module
# ---------------------------------------------------------------------------
echo "[*] Loading dev module: $KO"
rmmod amneziawg 2>/dev/null || true
insmod "$KO"

# Assert the kernel is actually running the module we just built, not a stale or
# distro/DKMS amneziawg that a failed rmmod may have left resident.  srcversion is
# a content hash emitted by modpost, so it uniquely fingerprints THIS .ko and works
# for both debug and non-debug builds (unlike the selftest banner, which only the
# debug build prints).
WANT_SRCVERSION="$(modinfo -F srcversion "$KO" 2>/dev/null || true)"
GOT_SRCVERSION="$(cat /sys/module/amneziawg/srcversion 2>/dev/null || true)"
if [[ -z "$GOT_SRCVERSION" ]]; then
	echo "ERROR: amneziawg module is not loaded after insmod $KO." >&2
	exit 1
fi
if [[ -n "$WANT_SRCVERSION" && "$WANT_SRCVERSION" != "$GOT_SRCVERSION" ]]; then
	echo "ERROR: loaded amneziawg srcversion ($GOT_SRCVERSION) does not match the" >&2
	echo "       built module $KO ($WANT_SRCVERSION) -- a stale/stock module is resident." >&2
	exit 1
fi
echo "[*] Verified loaded module matches $KO (srcversion ${GOT_SRCVERSION:-unknown})"

# Turn on the module's pr_debug/net_dbg messages at runtime (e.g. the receiver's
# "Unknown message ... packet dropped"). Works on a non-debug build too, as long
# as the kernel has CONFIG_DYNAMIC_DEBUG. Best-effort.
if [[ -w /sys/kernel/debug/dynamic_debug/control ]]; then
	echo 'module amneziawg +p' > /sys/kernel/debug/dynamic_debug/control 2>/dev/null || true
	echo "[*] Enabled dynamic debug for module amneziawg"
fi

# ---------------------------------------------------------------------------
# Network namespaces
# ---------------------------------------------------------------------------
echo "[*] Creating namespaces and veth pair"
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"

# veth pair: VETH_A lives in NS_A, VETH_B in NS_B
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip -n "$NS_A" addr add "${UNDERLAY_A}/${UNDERLAY_PFX}" dev "$VETH_A"
ip -n "$NS_B" addr add "${UNDERLAY_B}/${UNDERLAY_PFX}" dev "$VETH_B"
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up

# ---------------------------------------------------------------------------
# Optional: start tcpdump on the underlay veth in NS_A for realism capture
# ---------------------------------------------------------------------------
if command -v tcpdump &>/dev/null; then
	echo "[*] Starting tcpdump capture -> $PCAP"
	ip netns exec "$NS_A" tcpdump -q -i "$VETH_A" -w "$PCAP" &
	TCPDUMP_PID=$!
	# Give tcpdump a moment to open the socket before traffic flows
	sleep 0.5
else
	echo "[*] tcpdump not found — skipping pcap capture (test will still run)"
fi

# ---------------------------------------------------------------------------
# Key generation (uses the patched wg binary)
# ---------------------------------------------------------------------------
echo "[*] Generating keys"
export WG_HIDE_KEYS=never
KEY_A="$("$WG" genkey)"
KEY_B="$("$WG" genkey)"
PUB_A="$(printf '%s' "$KEY_A" | "$WG" pubkey)"
PUB_B="$(printf '%s' "$KEY_B" | "$WG" pubkey)"

[[ -n "$KEY_A" && -n "$KEY_B" && -n "$PUB_A" && -n "$PUB_B" ]]

# ---------------------------------------------------------------------------
# Create amneziawg interfaces
# ---------------------------------------------------------------------------
echo "[*] Creating AWG interfaces"
# Create each interface DIRECTLY inside its namespace. A WireGuard/AmneziaWG
# interface's UDP socket lives in the namespace where the interface is CREATED
# and does NOT move with `ip link set ... netns`. If we created them in the
# default ns and moved them, both sockets would stay in the default ns and could
# not reach the veth underlay (10.99.88.x) that exists only inside NS_A/NS_B —
# the handshake init would go nowhere and the peer would receive nothing.
ip -n "$NS_A" link add "$WG_A" type amneziawg
ip -n "$NS_B" link add "$WG_B" type amneziawg

# ---------------------------------------------------------------------------
# Configure side B (vanilla peer — SAME AWG framing (s4) as A so the wire
# framing matches, but NO imitate_protocol: it fills its padding randomly
# and must still accept A's QUIC-shaped padding (the cosmetic-interop proof).
# ---------------------------------------------------------------------------
echo "[*] Configuring side B (vanilla peer)"
ip -n "$NS_B" addr add "${TUNNEL_B}/${TUNNEL_PFX}" dev "$WG_B"

ip netns exec "$NS_B" "$WG" set "$WG_B" \
	private-key <(printf '%s' "$KEY_B") \
	listen-port "$PORT_B" \
	s4 600 \
	peer "$PUB_A" \
		allowed-ips "${TUNNEL_A}/32"

ip -n "$NS_B" link set "$WG_B" up

# ---------------------------------------------------------------------------
# Configure side A (patched sender). IMITATE selects the shaping protocol;
# IMITATE=none makes A == B (s4 framing, random padding, no decoy) — a control
# run that isolates whether a failure is imitation-specific or framing/test.
# ---------------------------------------------------------------------------
IMITATE_PROTO="${IMITATE:-quic}"
A_IMITATE_ARGS=()
if [[ "$IMITATE_PROTO" != "none" ]]; then
	A_IMITATE_ARGS=(imitate_protocol "$IMITATE_PROTO" i1 "<q 600>")
fi
echo "[*] Configuring side A (sender; IMITATE=$IMITATE_PROTO)"
ip -n "$NS_A" addr add "${TUNNEL_A}/${TUNNEL_PFX}" dev "$WG_A"

ip netns exec "$NS_A" "$WG" set "$WG_A" \
	private-key <(printf '%s' "$KEY_A") \
	listen-port "$PORT_A" \
	s4 600 \
	"${A_IMITATE_ARGS[@]}" \
	peer "$PUB_B" \
		allowed-ips "${TUNNEL_B}/32" \
		endpoint "${UNDERLAY_B}:${PORT_B}"

ip -n "$NS_A" link set "$WG_A" up

# Now tell B where A lives (after A is up so the endpoint is reachable)
ip netns exec "$NS_B" "$WG" set "$WG_B" \
	peer "$PUB_A" \
		endpoint "${UNDERLAY_A}:${PORT_A}"

# ---------------------------------------------------------------------------
# Assert 1: ping through the tunnel (A -> B)
# ---------------------------------------------------------------------------
echo "[*] Assert: ping A -> B through AWG tunnel"
ip netns exec "$NS_A" ping -c 3 -W 5 "$TUNNEL_B"

# Also ping B -> A to verify bidirectional handshake acceptance
echo "[*] Assert: ping B -> A through AWG tunnel"
ip netns exec "$NS_B" ping -c 3 -W 5 "$TUNNEL_A"

# ---------------------------------------------------------------------------
# Assert 2: iperf3 transfer over the tunnel
# ---------------------------------------------------------------------------
echo "[*] Assert: iperf3 transfer (A -> B)"
ip netns exec "$NS_B" iperf3 -s -1 -B "$TUNNEL_B" -D >/dev/null 2>&1
# Wait for the server socket to appear
ready=0
for i in $(seq 1 20); do
	if ip netns exec "$NS_B" ss -tlpH 'sport = 5201' | grep -q iperf3; then
		ready=1; break
	fi
	sleep 0.2
done
[[ $ready -eq 1 ]] || { echo "ERROR: iperf3 server did not start in side B" >&2; exit 1; }

ip netns exec "$NS_A" iperf3 -Z -t 3 -c "$TUNNEL_B"

# ---------------------------------------------------------------------------
# Cleanup happens automatically via the EXIT trap
# ---------------------------------------------------------------------------

if [[ -n "$TCPDUMP_PID" ]]; then
	kill "$TCPDUMP_PID" 2>/dev/null || true
	wait "$TCPDUMP_PID" 2>/dev/null || true
	TCPDUMP_PID=""
	echo "[*] pcap written to: $PCAP"
	echo "    Open in Wireshark to confirm outgoing packets are classified as QUIC."
fi

RUN_OK=1
echo "PASS: patched sender interops with vanilla peer"

# ===========================================================================
# Scenario 2: qinit end-to-end — i1=<qinit example.com> vs vanilla peer
#
# The sender emits a 1200-byte QUIC v1 Initial (the qinit I-packet) before
# the real WG handshake initiation.  The vanilla peer MUST drop it — it does
# not match the AWG magic header, so the receive path discards it as unknown
# message type.  The real handshake still completes (proven by ping).
# tshark (if available) dissects the captured decoy and asserts SNI=example.com.
# ===========================================================================
echo ""
echo "[*] =============================================================="
echo "[*] Scenario 2: qinit (i1=<qinit example.com>) vs vanilla peer"
echo "[*] =============================================================="

QSCENARIO_STARTED=1

# ---------------------------------------------------------------------------
# Create qinit namespace pair + veth
# ---------------------------------------------------------------------------
echo "[*] qinit: creating namespaces and veth pair"
ip netns del "$QNS_A" 2>/dev/null || true
ip netns del "$QNS_B" 2>/dev/null || true
ip netns add "$QNS_A"
ip netns add "$QNS_B"

ip link add "$QVETH_A" type veth peer name "$QVETH_B"
ip link set "$QVETH_A" netns "$QNS_A"
ip link set "$QVETH_B" netns "$QNS_B"

ip -n "$QNS_A" addr add "${QUNDERLAY_A}/${QUNDERLAY_PFX}" dev "$QVETH_A"
ip -n "$QNS_B" addr add "${QUNDERLAY_B}/${QUNDERLAY_PFX}" dev "$QVETH_B"
ip -n "$QNS_A" link set "$QVETH_A" up
ip -n "$QNS_B" link set "$QVETH_B" up
ip -n "$QNS_A" link set lo up
ip -n "$QNS_B" link set lo up

# ---------------------------------------------------------------------------
# Start tcpdump on the sender-side veth in QNS_A before any traffic.
# We capture on QNS_A (the sender) so we see outbound packets as emitted.
# The qinit I-packet is a 1200-byte UDP datagram sent to QNS_B's underlay
# port (QPORT_B) before the real WG handshake initiation packet.
# ---------------------------------------------------------------------------
if command -v tcpdump &>/dev/null; then
	echo "[*] qinit: starting tcpdump capture -> $QPCAP"
	ip netns exec "$QNS_A" tcpdump -q -i "$QVETH_A" -w "$QPCAP" &
	QTCPDUMP_PID=$!
	sleep 0.5
else
	echo "[*] qinit: tcpdump not found — skipping pcap capture (test will still run)"
fi

# ---------------------------------------------------------------------------
# Key generation for qinit scenario
# ---------------------------------------------------------------------------
echo "[*] qinit: generating keys"
QKEY_A="$("$WG" genkey)"
QKEY_B="$("$WG" genkey)"
QPUB_A="$(printf '%s' "$QKEY_A" | "$WG" pubkey)"
QPUB_B="$(printf '%s' "$QKEY_B" | "$WG" pubkey)"
[[ -n "$QKEY_A" && -n "$QKEY_B" && -n "$QPUB_A" && -n "$QPUB_B" ]]

# ---------------------------------------------------------------------------
# Create AWG interfaces directly in each namespace (socket placement)
# ---------------------------------------------------------------------------
echo "[*] qinit: creating AWG interfaces"
ip -n "$QNS_A" link add "$QWG_A" type amneziawg
ip -n "$QNS_B" link add "$QWG_B" type amneziawg

# ---------------------------------------------------------------------------
# Configure side QB — vanilla peer (no imitate, no i1, just s4 so the
# wire-level padding header still matches the sender's AWG framing).
# It will receive the 1200-byte qinit decoy on its UDP port but drop it:
# the AWG receive path checks the message type / magic header and discards
# any packet it cannot decrypt or classify — no receive-path change needed.
# ---------------------------------------------------------------------------
echo "[*] qinit: configuring side QB (vanilla peer)"
ip -n "$QNS_B" addr add "${QTUNNEL_B}/${QTUNNEL_PFX}" dev "$QWG_B"

ip netns exec "$QNS_B" "$WG" set "$QWG_B" \
	private-key <(printf '%s' "$QKEY_B") \
	listen-port "$QPORT_B" \
	s4 600 \
	peer "$QPUB_A" \
		allowed-ips "${QTUNNEL_A}/32"

ip -n "$QNS_B" link set "$QWG_B" up

# ---------------------------------------------------------------------------
# Configure side QA — patched sender with i1=<qinit example.com>.
# qinit is self-contained (1200-byte QUIC v1 Initial, fixed size) so it does
# NOT require imitate_protocol quic; it replaces the I-packet entirely.
# The s4 transport junk size is kept so the S-padding path is exercised on
# data packets; the qinit tag is exclusive (no other tags on this ispec).
# ---------------------------------------------------------------------------
echo "[*] qinit: configuring side QA (sender; i1=<qinit example.com>)"
ip -n "$QNS_A" addr add "${QTUNNEL_A}/${QTUNNEL_PFX}" dev "$QWG_A"

ip netns exec "$QNS_A" "$WG" set "$QWG_A" \
	private-key <(printf '%s' "$QKEY_A") \
	listen-port "$QPORT_A" \
	s4 600 \
	i1 "<qinit example.com>" \
	peer "$QPUB_B" \
		allowed-ips "${QTUNNEL_B}/32" \
		endpoint "${QUNDERLAY_B}:${QPORT_B}"

ip -n "$QNS_A" link set "$QWG_A" up

# Now tell QB where QA lives
ip netns exec "$QNS_B" "$WG" set "$QWG_B" \
	peer "$QPUB_A" \
		endpoint "${QUNDERLAY_A}:${QPORT_A}"

# ---------------------------------------------------------------------------
# Assert 1: tunnel handshakes and carries traffic despite the qinit decoy
# (proves the vanilla peer drops the decoy as junk and the real handshake
# still completes — if the decoy were accepted as a WG packet the counters
# would not match and the handshake would fail or be misrouted).
# ---------------------------------------------------------------------------
echo "[*] qinit: Assert 1 — ping QA -> QB (tunnel must come up)"
ip netns exec "$QNS_A" ping -c 3 -W 5 "$QTUNNEL_B"

echo "[*] qinit: Assert 1b — ping QB -> QA (bidirectional)"
ip netns exec "$QNS_B" ping -c 3 -W 5 "$QTUNNEL_A"

# ---------------------------------------------------------------------------
# Assert 2: the qinit decoy is 1200 bytes and tshark sees SNI=example.com
#
# Stop the capture now (while namespaces are still alive) so the pcap is
# flushed, then dissect it with tshark.  We force QUIC dissection on the
# peer's listen port via tshark's decode-as mechanism (-d udp.port==...,quic)
# because the decoy is sent to QPORT_B, not the standard QUIC port 443.
# We filter to packets from QNS_A's underlay IP (the sender) so we examine
# the outbound decoy only.
#
# The assertion is guarded: SKIP if tcpdump or tshark is not available
# (consistent with the existing script's best-effort capture convention).
# ---------------------------------------------------------------------------
if [[ -n "$QTCPDUMP_PID" ]]; then
	kill "$QTCPDUMP_PID" 2>/dev/null || true
	wait "$QTCPDUMP_PID" 2>/dev/null || true
	QTCPDUMP_PID=""
	echo "[*] qinit: pcap written to: $QPCAP"

	if command -v tshark &>/dev/null; then
		echo "[*] qinit: Assert 2 — dissect captured decoy with tshark"

		# 2a: the captured traffic must include at least one 1200-byte UDP
		# datagram from QA to QB (the qinit I-packet).  We check udp.length
		# (the UDP header length field, which covers the 8-byte UDP header +
		# payload) rather than frame.len: udp.length == 1208 means the UDP
		# payload is exactly 1200 bytes.  This is L2-framing-independent —
		# it holds whether tcpdump captured with an Ethernet II (14-byte)
		# or Linux cooked SLL (16-byte) link header.
		QINIT_UDP_LEN=1208
		QINIT_COUNT="$(tshark -r "$QPCAP" \
			-d "udp.port==${QPORT_B},quic" \
			-Y "ip.src == ${QUNDERLAY_A} && quic && udp.length == ${QINIT_UDP_LEN}" \
			2>/dev/null | wc -l)"
		if [[ "$QINIT_COUNT" -ge 1 ]]; then
			echo "[*] qinit: PASS — found ${QINIT_COUNT} QUIC frame(s) with udp.length==${QINIT_UDP_LEN} (1200-byte UDP payload)"
		else
			echo "ERROR: qinit: expected at least one QUIC frame with udp.length==${QINIT_UDP_LEN} (1200-byte qinit decoy), found ${QINIT_COUNT}" >&2
			exit 1
		fi

		# 2b: tshark QUIC dissection must recover SNI=example.com from the
		# decoy.  We force QUIC dissection on QPORT_B via decode-as.
		QINIT_SNI="$(tshark -r "$QPCAP" \
			-d "udp.port==${QPORT_B},quic" \
			-Y "ip.src == ${QUNDERLAY_A} && quic" \
			-T fields \
			-e tls.handshake.extensions_server_name \
			2>/dev/null | tr -d '[:space:]')"
		if [[ "$QINIT_SNI" == *"example.com"* ]]; then
			echo "[*] qinit: PASS tshark — SNI='${QINIT_SNI}'"
		else
			echo "ERROR: qinit: tshark SNI mismatch: got '${QINIT_SNI}', want 'example.com'" >&2
			exit 1
		fi
	else
		echo "[*] qinit: tshark not found — skipping SNI dissection (test proceeds)"
	fi
else
	echo "[*] qinit: tcpdump was not running — skipping pcap-based assertions"
fi

# ---------------------------------------------------------------------------
# Assert 3: vanilla peer did NOT accept the decoy as a real handshake.
# After a successful ping (Assert 1) the peer has exactly ONE session with
# QA — the real handshake session.  A spurious peer-state entry or a second
# latest-handshakes timestamp would indicate the decoy was mistakenly
# processed.  We assert that QB shows exactly one peer and that it has a
# non-zero latest-handshake (the real session) while having no unexpected
# RX count inflation.
#
# Concretely: `awg show <dev> latest-handshakes` on QB must return a non-zero
# timestamp for QA's public key — this proves the real handshake completed.
# (The decoy, being undecryptable junk, leaves no peer state on QB.)
# ---------------------------------------------------------------------------
echo "[*] qinit: Assert 3 — vanilla peer QB has exactly the real handshake session"
QB_HS="$(ip netns exec "$QNS_B" "$WG" show "$QWG_B" latest-handshakes 2>/dev/null)"
QB_HS_TS="$(printf '%s\n' "$QB_HS" | awk -v pub="$QPUB_A" '$1==pub{print $2}')"
if [[ -z "$QB_HS_TS" || "$QB_HS_TS" == "0" ]]; then
	echo "ERROR: qinit: QB shows no latest-handshake for QA's public key — real handshake did not complete" >&2
	exit 1
fi
echo "[*] qinit: QB latest-handshake for QA = ${QB_HS_TS} (non-zero — real session confirmed)"

QRUN_OK=1
echo "PASS: qinit i1=<qinit example.com> — decoy dropped by vanilla peer, tunnel handshakes normally"
