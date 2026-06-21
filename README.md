# AmneziaWG kernel module

> **This `-proxy` fork** adds **native client-side traffic imitation** to the
> AmneziaWG kernel module. On top of AmneziaWG's byte-signature obfuscation, this
> fork can shape the obfuscation padding and junk packets to resemble real
> **QUIC / DNS / STUN / SIP**, and can emit a fake **QUIC Initial advertising a
> benign SNI** (`qinit`). Unlike the userspace
> [`amneziawg-go-proxy`](https://github.com/creatorofuniverses/amneziawg-go-proxy)
> fork, these features run **inside the kernel module itself**, so the patched side
> shapes its own client → server traffic with no userspace daemon. Everything here
> is **opt-in and off by default, sender-only, and length-invariant** — an imitating
> peer interoperates with a stock (vanilla) AmneziaWG/WireGuard peer unchanged. See
> [Traffic imitation](#traffic-imitation).

## Table of contents

- [Installation](#installation) (package repos — ~~struck through, see note~~)
  - [~~Ubuntu~~](#ubuntu)
  - [~~Debian~~](#debian)
  - [~~Linux Mint~~](#linux-mint)
  - [~~RHEL/CentOS/SUSE/Fedora Core~~](#rhelcentossusefedora-core)
- [Manual build](#manual-build)
- [Configuration](#configuration)
- [Traffic imitation](#traffic-imitation)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Installation

> [!WARNING]
> The package-repository installs below (PPA / COPR) deliver **upstream AmneziaWG**, not this
> `-proxy` fork, so they will **not** install the traffic-imitation features. They are struck
> through and kept for reference only. **For now, use [Manual build](#manual-build).**

### ~~Ubuntu~~

~~Open `Terminal` and proceed with following instructions:~~

1. ~~(Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
After kernel upgrade reboot is required.~~
2. ~~Ensure that you have source repositories configured for APT - run `vi /etc/apt/sources.list` and make sure that there is
at least one line starting with `deb-src` is present and uncommented.~~
3. ~~Install pre-requisites - run `sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)`.~~
4. ~~Run `sudo add-apt-repository ppa:amnezia/ppa`.~~
5. ~~Finally execute `sudo apt-get install -y amneziawg`.~~

### ~~Debian~~

~~Open `Terminal` and do next steps:~~

1. ~~(Optionally) Upgrade your system to latest packages including latest available kernel by running `apt-get full-upgrade`.
   After kernel upgrade reboot is required.~~
2. ~~Ensure that you have source repositories configured for APT - run `vi /etc/apt/sources.list` and make sure that there is
   at least one line starting with `deb-src` is present and uncommented.~~
3. ~~Execute following commands:~~
```shell
sudo apt install -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r)
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update
sudo apt-get install -y amneziawg
```

### ~~Linux Mint~~

~~Open `Software Sources` and make sure that `Source code repositories` (under `Optional Sources`) are enabled.~~

~~Proceed to `PPAs` section and add `ppa:amnezia/ppa` PPA repository, after that save configuration and rebuild `apt` cache.~~

~~After that, open `Terminal` and run:~~

```shell
sudo apt-get install -y amneziawg
```

### ~~RHEL/CentOS/SUSE/Fedora Core~~

~~*If you use release that doesn't have DKMS support out of the box, you may need to install [EPEL](https://docs.fedoraproject.org/en-US/epel/#_quickstart) first.*~~

~~Open `Terminal` and run:~~

```shell
sudo dnf copr enable amneziavpn/amneziawg
sudo dnf install amneziawg-dkms amneziawg-tools
```

~~Before installation it is strictly recommended to upgrade your system kernel to the latest available version and perform
the reboot afterwards.~~

## Manual build

You may need to install kernel headers and/or build essentials packages before running following steps.

> [!TIP]
> Building on the target machine requires a full toolchain and kernel source tree there, which is slow.
> To make it quicker you can **cross-build on your workstation** and copy only the resulting `amneziawg.ko`
> to the server — see [Building locally and deploying to a server](BUILDING-LOCALLY.md).

1. In Terminal:
    ```shell
    git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
    cd amneziawg-linux-kernel-module/src
    ```

2. Now, if you run modern Linux with kernel version 5.6+, you need to download your kernel's source from anywhere possible
and link resulting tree to `kernel` symlink:
    
    ```shell
    ln -s /path/to/kernel/source kernel
    ```
    
    Please note to find and provide full kernel sourcetree, not only headers. **If you run on legacy kernel (<5.6), you do not need to perform this step.**

    Where to get the source (pick whichever matches your running kernel — check it with `uname -r`):

    - **Your distribution** ships a matching source package, which is usually the safest choice because it includes the distro's patches:
        - Debian/Ubuntu: `sudo apt install linux-source` (unpacks to `/usr/src/linux-source-*.tar.*`).
        - Fedora/RHEL: `sudo dnf install kernel-devel` for the prepared build tree under `/usr/src/kernels/$(uname -r)`.
        - Arch: the `linux-headers` package provides a build tree at `/usr/lib/modules/$(uname -r)/build`.
    - **kernel.org** hosts the upstream (vanilla) tarballs. This one-liner downloads, unpacks, and links the source that matches your running kernel version:
        ```shell
        VER=$(uname -r | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?'); \
        curl -O "https://cdn.kernel.org/pub/linux/kernel/v${VER%%.*}.x/linux-${VER}.tar.xz" && \
        tar xf "linux-${VER}.tar.xz" && ln -sf "$PWD/linux-${VER}" kernel
        ```
        Note that a vanilla tree may not exactly match a heavily patched distro kernel; prefer your distribution's source package if the build complains about a version mismatch.

3. Now perform build and installation:
    ```shell
    make
    sudo make install
    ```
   
    Or on a capable system you may want to use DKMS for this:
    ```shell
    sudo make dkms-install
    sudo dkms add -m amneziawg -v 1.0.0
    sudo dkms build -m amneziawg -v 1.0.0
    sudo dkms install -m amneziawg -v 1.0.0
    ```

    `sudo make dkms-install` copies the module sources to `/usr/src/amneziawg-1.0.0`, which is what the
    subsequent `dkms add` expects — run it as root, and if `dkms add` reports *"module source directory does
    not exist"* it means this step did not complete.

### DKMS vs. plain install — which to choose?

- **Plain `make install`** builds the module once against your *current* kernel and copies it into
  `/lib/modules/$(uname -r)`. It is simple, but the module is tied to that one kernel: after a kernel
  upgrade the module is gone and you must rebuild and reinstall it manually.
- **DKMS** registers the *sources* and rebuilds the module **automatically every time the kernel is
  updated**, so the tunnel keeps working across upgrades. It costs a little more setup and requires a
  toolchain to stay installed on the machine. Prefer DKMS on long-lived servers and desktops you keep
  updated; plain install is fine for one-off or throwaway builds.

### Verifying the installation

After either method, confirm the module is present and loadable:

```shell
# 1. The module is registered with the kernel (a path is printed):
modinfo amneziawg | head -n 5

# 2. Load it (no output means success):
sudo modprobe amneziawg

# 3. It is now loaded:
lsmod | grep amneziawg

# 4. For DKMS, check the build status shows "installed" for your kernel:
dkms status amneziawg
```

You can also create a test interface to confirm the userspace tooling sees it:

```shell
sudo ip link add dev awg0 type amneziawg && ip link show awg0 && sudo ip link del awg0
```

If `modprobe` fails with *"version magic"* or *"disagrees about version of symbol"*, the module was built
against a different kernel than the one running — rebuild against the correct kernel tree (see step 2 and
[Building locally and deploying to a server](BUILDING-LOCALLY.md)).

## Configuration

> [!IMPORTANT]
> All parameters must be the same between Client and Server, except for Jc, Jmin, and Jmax - these may vary.

- Jc — 1 ≤ Jc ≤ 128; recommended range is from 4 to 12 inclusive
- Jmin — Jmax > Jmin < 1280*; recommended value is 8
- Jmax — Jmin < Jmax ≤ 1280*; recommended value is 80
- S1 — S1 ≤ 1132* (1280* - 148 = 1132); S1 + 56 ≠ S2; recommended range is from 15 to 150 inclusive
- S2 — S2 ≤ 1188* (1280* - 92 = 1188); recommended range is from 15 to 150 inclusive
- H1/H2/H3/H4 — must be unique among each other; recommended range is from 5 to 2147483647 inclusive

`* Assuming a basic internet connection with an MTU value of 1280.`

## Traffic imitation

> Added by this fork. Off by default — omit these settings and behaviour is identical to upstream AmneziaWG.

AmneziaWG already defeats *byte-signature* DPI (its `S` padding and `H` header
randomization remove WireGuard's fixed fields), but the padding and junk it sends
are still high-entropy bytes a censor can classify as **"unknown encrypted."**
Traffic imitation closes that gap directly in the kernel module: it rewrites those
bytes into **protocol-conformant filler** so the flow resembles an allowed protocol
(QUIC/DNS/STUN/SIP), and can send a fake **QUIC Initial carrying a benign SNI**.

The rewrite is **cosmetic, sender-only, and length-invariant**: a receiver only
size-matches the padding and validates the magic header *after* it, never inspecting
padding content — so an imitating peer **interoperates with a stock (vanilla) peer
unchanged**. Enable it on the client alone, against an unmodified server.

| DPI technique | Addressed by |
|---|---|
| Byte-signature (WireGuard fixed fields) | AmneziaWG itself (`S` / `H`) — already shipped |
| Protocol-positive ("is this an allowed protocol?") | `imitate_protocol` + the `q`/`dns`/`stun`/`sip` I-packet tags |
| Cheap line-rate SNI filtering | the `qinit` I-packet tag (fake QUIC Initial carrying that SNI) |
| Statistical / behavioural (sizes, timing, duration) | **Nothing here** — out of scope |

Configure these with the matching tools fork
[`amneziawg-tools-proxy`](https://github.com/creatorofuniverses/amneziawg-tools-proxy),
which forwards the keys to the module over netlink.

### `imitate_protocol`

A device-level setting that shapes the obfuscation padding (`S1`–`S4`) and the junk
packets to resemble the chosen protocol (default `none`):

```
imitate_protocol = none | quic | dns | stun | sip
```

### Imitation I-packets (`I1`–`I5`)

The `<q>` / `<dns>` / `<stun>` / `<sip>` / `<qinit>` tags plug into the existing
`I1`–`I5` descriptor mechanism — **no netlink/ABI change and no tools change**,
because `I1`–`I5` are already standard keys whose values are forwarded verbatim:

```
awg set <iface> i1='<qinit example.com>'
awg set <iface> i2='<q 600>'
```

`<qinit domain>` builds a complete, header-protected **QUIC v1 Initial** datagram
(fixed 1200 bytes) carrying a TLS 1.3 ClientHello that advertises `domain` as its
SNI. It derives keys from the public RFC 9001 Initial salt, so any observer can read
the SNI — which is the point: the decoy looks like a real browser opening an HTTP/3
connection to an innocuous host, defeating cheap line-rate SNI filtering. `qinit`
must be the **sole** tag in its I-packet (it is a complete, self-contained datagram).

**Caveats:** the fake handshake never completes, so a censor running a full QUIC
state machine is unaffected; and the ClientHello's TLS fingerprint (JA3/JA4) is a
fixed generic one, not a specific browser's (matching a real browser is planned
follow-on work). The vendored crypto (AES-128 / SHA-256 / HMAC / HKDF / AES-128-GCM)
is software-only with no `CONFIG_CRYPTO_*` dependency, and is validated by NIST/FIPS/
RFC known-answer tests, the RFC 9001 Appendix A.1 key-schedule vector, and a
byte-exact golden vector cross-checked against the
[`amneziawg-go-proxy`](https://github.com/creatorofuniverses/amneziawg-go-proxy) oracle
(plus independent aioquic + tshark decode of the generated datagram).

## Troubleshooting

> [!TIP]
> Please check [Ubuntu Server documentation](https://documentation.ubuntu.com/server/how-to/wireguard-vpn/troubleshooting) for more troubleshooting steps.

### Enable debug logging

To get more details, you can enable the dynamic debug feature for the module:

```shell
echo "module amneziawg +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

This will log messages to dmesg, which can be watched live with:
```shell
dmesg -wT
```

### Low space on `/tmp` filesystem

Most installation instructions above assume that you have enough space in system's `/tmp` partition (as setup script needs 
to manipulate with kernel's sourcetree which is pretty huge).

If you can not afford enough space in your `/tmp`, you may override temporary dir by setting `AWG_TEMP_DIR` environment variable
before the installation:

```shell
export AWG_TEMP_DIR="/home/ubuntu/tmp"
```

This setting should persist for future and will not require repeating.

### Kernel sourcetree could not be found automatically

In some rare cases, setup script may not find your kernel's sourcetree automatically. You may find appropriate sources by yourself
then and link them to DKMS module sources, e.g.

```shell
ln -s /path/to/your/kernel/sources /usr/src/amneziawg-1.0.0/kernel
```

Reinstall the package thereafter and you should get everything working.

Should you upgrade your kernel in the future, please remember that you may also need refresh sourcetree and update symlinks.

## License

This project is released under the [GPLv2](COPYING).
