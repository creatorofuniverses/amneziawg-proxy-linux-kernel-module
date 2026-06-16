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

# ---------------------------------------------------------------------------
# Cleanup trap  (runs on EXIT regardless of success or failure)
# ---------------------------------------------------------------------------
cleanup() {
	set +e
	# Stop tcpdump if it was started
	if [[ -n "$TCPDUMP_PID" ]]; then
		kill "$TCPDUMP_PID" 2>/dev/null
		wait "$TCPDUMP_PID" 2>/dev/null
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
	# Unload the dev module.
	# NOTE: the system module (if any) is NOT restored automatically.
	#       If you need it back, run: modprobe amneziawg
	rmmod amneziawg 2>/dev/null || true
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
# Configure side B (vanilla AWG peer — no imitate settings)
# ---------------------------------------------------------------------------
echo "[*] Configuring side B (vanilla peer)"
ip -n "$NS_B" addr add "${TUNNEL_B}/${TUNNEL_PFX}" dev "$WG_B"

ip netns exec "$NS_B" "$WG" set "$WG_B" \
	private-key <(printf '%s' "$KEY_B") \
	listen-port "$PORT_B" \
	peer "$PUB_A" \
		allowed-ips "${TUNNEL_A}/32"

ip -n "$NS_B" link set "$WG_B" up

# ---------------------------------------------------------------------------
# Configure side A (patched sender: imitate_protocol quic + s4 + i1 decoy)
# ---------------------------------------------------------------------------
echo "[*] Configuring side A (patched sender with imitate)"
ip -n "$NS_A" addr add "${TUNNEL_A}/${TUNNEL_PFX}" dev "$WG_A"

ip netns exec "$NS_A" "$WG" set "$WG_A" \
	private-key <(printf '%s' "$KEY_A") \
	listen-port "$PORT_A" \
	s4 600 \
	imitate_protocol quic \
	i1 "<q 600>" \
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
ip netns exec "$NS_B" iperf3 -s -1 -B "$TUNNEL_B" -D --logfile /tmp/iperf3-b-$$.log
# Wait for the server socket to appear
for i in $(seq 1 20); do
	if ip netns exec "$NS_B" ss -tlpH 'sport = 5201' | grep -q iperf3; then
		break
	fi
	sleep 0.2
done

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

echo "PASS: patched sender interops with vanilla peer"
