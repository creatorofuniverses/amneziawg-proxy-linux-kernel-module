#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
qinit_interop.py — Layer-3 independent-decoder gate for QUIC Initial datagrams.

Reads a 1200-byte QUIC v1 Initial datagram (default: testdata/qinit_vector.bin)
and runs two independent decoders:

  * aioquic path  — derives Initial keys, removes header protection, AEAD-opens
                    the payload, parses the TLS ClientHello, asserts
                    server_name == "example.com" and ALPN contains "h3".
  * tshark path   — wraps the datagram in a minimal pcap (via text2pcap),
                    dissects it with tshark, and asserts "example.com" appears
                    in the SNI field.

Exit 0  if every available decoder that runs succeeds.
Exit 1  if any available decoder FAILS to find the expected SNI.
A decoder is SKIPped (not a failure) only when the required tool is absent.
"""

import os
import struct
import subprocess
import sys
import tempfile

EXPECTED_SNI = "example.com"
EXPECTED_ALPN = "h3"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_available(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0


def _load_datagram(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 1200:
        raise ValueError(f"Expected 1200-byte datagram, got {len(data)}")
    return data


# ---------------------------------------------------------------------------
# aioquic path
# ---------------------------------------------------------------------------

def _decode_aioquic(data):
    """
    Derive QUIC Initial keys from the DCID, remove header protection,
    AEAD-open the payload, parse the TLS ClientHello, and return
    (server_name, alpn_protocols).

    Uses only aioquic primitives (CryptoContext, hkdf_*, pull_client_hello)
    and the cryptography library — not our own C implementation.
    """
    from aioquic.quic.crypto import (
        CryptoContext,
        INITIAL_CIPHER_SUITE,
        QuicProtocolVersion,
        hkdf_extract,
        hkdf_expand_label,
        INITIAL_SALT_VERSION_1,
    )
    from aioquic.tls import Buffer, pull_client_hello
    from cryptography.hazmat.primitives import hashes

    # --- Parse the Long Header ---
    # byte0(1) version(4) dcid_len(1) dcid(dcid_len) scid_len(1) scid(scid_len)
    # token_len(varint) length(varint) packet_number(1-4 bytes, protected)
    dcid_len = data[5]
    dcid = data[6 : 6 + dcid_len]

    # --- Derive client Initial secret (RFC 9001 §5.2) ---
    algo = hashes.SHA256()
    initial_secret = hkdf_extract(algo, INITIAL_SALT_VERSION_1, dcid)
    client_secret = hkdf_expand_label(algo, initial_secret, b"client in", b"", 32)

    # --- Setup CryptoContext and decrypt ---
    # encrypted_offset = byte offset of the (protected) PN field.
    # Our fixed layout: 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2 = 26
    # (byte0, version, dcid_len, dcid, scid_len, scid, token_len=0, length varint=2B)
    pn_offset = 1 + 4 + 1 + dcid_len + 1 + data[6 + dcid_len] + 1 + 2
    ctx = CryptoContext()
    ctx.setup(
        cipher_suite=INITIAL_CIPHER_SUITE,
        secret=client_secret,
        version=int(QuicProtocolVersion.VERSION_1),
    )
    _, payload, _, _ = ctx.decrypt_packet(
        packet=bytes(data),
        encrypted_offset=pn_offset,
        expected_packet_number=0,
    )

    # --- Unwrap QUIC CRYPTO frame (type 0x06) ---
    # Frame: type(varint) offset(varint) length(varint) data
    # Our build always emits a single CRYPTO frame at the very start.
    pos = 0
    if payload[pos] != 0x06:
        raise ValueError(f"Expected CRYPTO frame (0x06), got {hex(payload[pos])}")
    pos += 1
    # offset varint (always 0 in our build)
    b = payload[pos]
    if b & 0xC0 == 0x00:
        pos += 1
    elif b & 0xC0 == 0x40:
        pos += 2
    elif b & 0xC0 == 0x80:
        pos += 4
    else:
        pos += 8
    # length varint
    b = payload[pos]
    if b & 0xC0 == 0x00:
        crypto_len = b
        pos += 1
    elif b & 0xC0 == 0x40:
        crypto_len = ((b & 0x3F) << 8) | payload[pos + 1]
        pos += 2
    elif b & 0xC0 == 0x80:
        crypto_len = ((b & 0x3F) << 24 | payload[pos+1] << 16 |
                      payload[pos+2] << 8 | payload[pos+3])
        pos += 4
    else:
        crypto_len = ((b & 0x3F) << 56 | payload[pos+1] << 48 |
                      payload[pos+2] << 40 | payload[pos+3] << 32 |
                      payload[pos+4] << 24 | payload[pos+5] << 16 |
                      payload[pos+6] << 8 | payload[pos+7])
        pos += 8
    tls_data = payload[pos : pos + crypto_len]

    # --- Parse TLS ClientHello ---
    buf = Buffer(data=tls_data)
    ch = pull_client_hello(buf)
    return ch.server_name, ch.alpn_protocols or []


def run_aioquic(data):
    """Run the aioquic decode gate. Returns (passed, message)."""
    try:
        import aioquic  # noqa: F401
    except ImportError:
        return None, "SKIP aioquic: package not installed (pip install aioquic)"

    try:
        sni, alpn = _decode_aioquic(data)
    except Exception as exc:
        return False, f"FAIL aioquic: exception during decode: {exc}"

    sni_ok = sni == EXPECTED_SNI
    alpn_ok = EXPECTED_ALPN in alpn

    if sni_ok and alpn_ok:
        return True, (
            f"PASS aioquic: SNI={sni!r}  ALPN={alpn}"
        )
    parts = []
    if not sni_ok:
        parts.append(f"SNI={sni!r} (want {EXPECTED_SNI!r})")
    if not alpn_ok:
        parts.append(f"ALPN={alpn} (want {EXPECTED_ALPN!r})")
    return False, "FAIL aioquic: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# tshark path
# ---------------------------------------------------------------------------

def _build_hex_dump(data):
    """Return a text2pcap-compatible hex dump of data."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{i:08x}  {hex_part}")
    return "\n".join(lines) + "\n"


def run_tshark(data):
    """Wrap datagram in a pcap and dissect with tshark. Returns (passed, message)."""
    if not _tool_available("tshark"):
        return None, "SKIP tshark: binary not found in PATH"
    if not _tool_available("text2pcap"):
        return None, "SKIP tshark: text2pcap not found (required for pcap synthesis)"

    hex_dump = _build_hex_dump(data)
    tmpdir = tempfile.mkdtemp()
    hexfile = os.path.join(tmpdir, "pkt.hex")
    pcapfile = os.path.join(tmpdir, "pkt.pcap")

    try:
        with open(hexfile, "w") as f:
            f.write(hex_dump)

        # Build a UDP/IPv4/Ethernet pcap (dst port 443 → QUIC)
        r = subprocess.run(
            ["text2pcap", "-u", "54321,443", hexfile, pcapfile],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            return False, f"FAIL tshark: text2pcap failed: {r.stderr.strip()}"

        r = subprocess.run(
            [
                "tshark", "-r", pcapfile,
                "-Y", "quic",
                "-T", "fields",
                "-e", "tls.handshake.extensions_server_name",
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            return False, f"FAIL tshark: tshark exited {r.returncode}: {r.stderr.strip()}"

        sni_field = r.stdout.strip()
        if EXPECTED_SNI in sni_field.split("\n"):
            return True, f"PASS tshark: SNI={sni_field!r}"
        return False, f"FAIL tshark: SNI field={sni_field!r} (want {EXPECTED_SNI!r})"

    finally:
        for p in (hexfile, pcapfile):
            if os.path.exists(p):
                os.unlink(p)
        os.rmdir(tmpdir)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_vector = os.path.join(script_dir, "testdata", "qinit_vector.bin")
    path = sys.argv[1] if len(sys.argv) > 1 else default_vector

    print(f"qinit_interop: decoding {path}")
    try:
        data = _load_datagram(path)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    results = []
    for decoder_fn in (run_aioquic, run_tshark):
        passed, msg = decoder_fn(data)
        print(msg)
        results.append((passed, msg))

    # Any available decoder that ran must PASS
    failures = [r for r in results if r[0] is False]
    if failures:
        sys.exit(1)

    ran = [r for r in results if r[0] is not None]
    if not ran:
        print("ERROR: no decoders available (install aioquic and/or tshark)", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
