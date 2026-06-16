#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Interop anchor for client-side traffic imitation (Tiers 1-3).
#
# DESCRIPTION
#   Creates two network namespaces connected by a veth pair.  Side A is
#   the "patched sender" configured with imitate_protocol quic, an S4
#   transport junk size (non-zero so the S-padding path is exercised), and
#   an I1 decoy packet descriptor.  Side B is a vanilla AWG peer with no
#   imitate settings, proving that shaped packets are still accepted by a
#   peer that does not shape.
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

# ---------------------------------------------------------------------------
# Cleanup trap  (runs on EXIT regardless of success or failure)
# ---------------------------------------------------------------------------
cleanup() {
	set +e
	# Stop tcpdump first so the pcap is flushed before we read/keep it
	if [[ -n "$TCPDUMP_PID" ]]; then
		kill "$TCPDUMP_PID" 2>/dev/null
		wait "$TCPDUMP_PID" 2>/dev/null
	fi
	# If the test did not reach the PASS line, dump evidence while the
	# namespaces and interfaces still exist (before we tear them down).
	if [[ "$RUN_OK" -ne 1 ]]; then
		dump_diag
	fi
	# Kill any processes still running inside the namespaces
	local pids
	pids="$(ip netns pids "$NS_A" 2>/dev/null) $(ip netns pids "$NS_B" 2>/dev/null)"
	if [[ -n "${pids// /}" ]]; then
		# shellcheck disable=SC2086
		kill $pids 2>/dev/null || true
	fi
	# Delete AWG interfaces (best-effort; they go away with the namespace anyway)
	ip -n "$NS_A" link del "$WG_A" 2>/dev/null || true
	ip -n "$NS_B" link del "$WG_B" 2>/dev/null || true
	# Delete namespaces (this also removes the veth endpoints)
	ip netns del "$NS_A" 2>/dev/null || true
	ip netns del "$NS_B" 2>/dev/null || true
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
# Create in default ns, then move into each namespace
ip link add "$WG_A" type amneziawg
ip link set "$WG_A" netns "$NS_A"
ip link add "$WG_B" type amneziawg
ip link set "$WG_B" netns "$NS_B"

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
