# Building the module locally and deploying to a server

Building the kernel module on the target server works, but it requires a
compiler toolchain, kernel headers, and a full kernel source tree on that
machine — which is slow to set up and undesirable on a minimal/hardened server.

A faster alternative is to **cross-build on your workstation** (which already
has a toolchain) and ship only the resulting `amneziawg.ko` to the server via
`rsync`/`scp`. This page explains how to do that safely.

> [!IMPORTANT]
> A kernel module is tightly coupled to the kernel it loads into. You must build
> against the **target server's exact kernel**, not your workstation's. Building
> against your local kernel and copying the `.ko` to a server running a different
> kernel **will not work** — the load is rejected.

## What has to match

Every `.ko` carries a *vermagic* string and symbol versions that the kernel
verifies at load time. A mismatch produces errors like
`version magic '...' should be '...'` or
`disagrees about version of symbol ...`. To avoid them, the build environment
must match the target in:

1. **Kernel release string** (`uname -r` on the server) — exactly, *including*
   the distro suffix (e.g. `6.6.30-1-amd64`, not just `6.6.30`). This is the one
   that bites most often.
2. **Kernel build config** (`CONFIG_*`) — especially `CONFIG_MODVERSIONS`,
   `CONFIG_MODULE_SIG`, and any option that changes struct layout. This comes
   from the kernel tree you point the `kernel` symlink / `KERNELDIR` at.
3. **Architecture** — your workstation and the server must be the same arch
   (e.g. both `x86_64`). If not, you need a cross-compiler (`ARCH=` + `CROSS_COMPILE=`).
4. **Compiler** — ideally the same major GCC version the target kernel was built
   with. Minor differences are usually tolerated; a large gap can cause subtle
   issues.

## Step 1 — get the server's exact kernel tree onto your workstation

Find the server's kernel version:

```shell
ssh user@server uname -r        # e.g. 6.6.30-1-amd64
```

Then obtain the **matching** source/headers tree. Pick one:

- **Copy the server's prepared build tree** (most reliable — it already carries
  the exact config and version info):
  ```shell
  rsync -a user@server:/usr/src/linux-headers-$(ssh user@server uname -r)/ ./target-kernel/
  # Debian/Ubuntu path shown; on Fedora/RHEL it is /usr/src/kernels/$(uname -r)/
  ```
- **Install the distro's source package locally**, matching the server's version
  (Debian/Ubuntu `linux-source`, Fedora/RHEL `kernel-devel`, Arch `linux-headers`).
- **Download the vanilla tarball** from kernel.org matching the version — only
  works cleanly if the server runs an unpatched mainline/stable kernel.

## Step 2 — build against that tree

From `src/`:

```shell
ln -sf "$PWD/../target-kernel" kernel
make KERNELDIR="$PWD/../target-kernel"
```

This produces `src/amneziawg.ko` built for the server's kernel.

## Step 3 — ship it and load it

```shell
rsync src/amneziawg.ko user@server:/tmp/

# On the server:
sudo insmod /tmp/amneziawg.ko            # quick test load
# or install it permanently:
sudo install -m644 /tmp/amneziawg.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a
sudo modprobe amneziawg
```

If `insmod` complains about version magic or symbol versions, the build tree
did not match the server's running kernel — recheck Step 1.

## Alternative: DKMS on the server

If you control the server and want the module to **survive kernel upgrades**
automatically, ship the *source* instead of a binary and let DKMS rebuild it
against whatever kernel is running:

```shell
sudo make dkms-install
sudo dkms add   -m amneziawg -v 1.0.0
sudo dkms build -m amneziawg -v 1.0.0
sudo dkms install -m amneziawg -v 1.0.0
```

This sidesteps every version-matching concern and is the most robust option for
a long-lived server — at the cost of needing a toolchain on the server. Use the
cross-build flow above when you specifically want to keep the server minimal.
