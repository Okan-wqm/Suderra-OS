# Kernel pins: one 6.12 line, hash-pinned, series-checked

ADR-048 DEC-8.12 (EI-028, EI-051, EI-089). Every Suderra OS kernel is the 6.12
LTS series, pinned by source and by hash, and `scripts/ci/check-kernel-config.py`
(`static`, run by `tests/image-contracts/kernel-config-contract-test.sh` on every
PR) fails a defconfig whose kernel is not.

## The pins

| Images | Source | Pin | Series | Hash |
|---|---|---|---|---|
| every x86 image, the generic aarch64 template | kernel.org `linux-6.12.114.tar.xz` (`BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE`) | version | 6.12 | equal to its line in `sha256sums.asc` of `cdn.kernel.org/pub/linux/kernel/v6.x`, whose autosigner signature verified (`linux.hash`) |
| RevPi Connect 4 | KUNBUS `revpi-6.12`, tag `v6.12.91-revpi0` | commit `756591ec4845ec0114ee7a3a99768f69bcd8bed3` (GitLab archive) | 6.12 | computed from the downloaded archive |
| Raspberry Pi 4 / CM4 | `raspberrypi/linux` | commit `576cc10e1ed50a9eacffc7a05c796051d7343ea4` (GitHub archive) | **6.6** (6.6.28) | computed from the downloaded archive |

The Raspberry Pi 4 / CM4 row is the one that is not on the 6.12 line: its images
build a 6.6.28 kernel with 6.12 toolchain headers. The checker lists it as a
tracked gap (`KNOWN_SERIES_GAPS`, finding EI-089), fails the day the pin and the
headers agree while the entry is still there, and fails for any other tarball
kernel whose series is not its headers'.

## What a pin has to carry

- `BR2_DOWNLOAD_FORCE_CHECK_HASHES=y` and `BR2_GLOBAL_PATCH_DIR` pointing at
  `board/suderra/buildroot-hashes` in every defconfig, so Buildroot refuses an archive
  without a `sha256` line (`linux.hash`).
- For a kernel.org kernel, the exact version; its series is in its name and must equal
  the `BR2_KERNEL_HEADERS_<major>_<minor>` of the defconfig.
- For a tarball kernel (a commit says nothing about its series), a
  `# kernel-series: X.Y` comment line right above its `sha256` line. Read it from the
  commit's own Makefile when the pin is made, never from the branch name:

  ```sh
  curl -sS https://raw.githubusercontent.com/raspberrypi/linux/<commit>/Makefile | sed -n 2,4p
  curl -sS https://gitlab.com/revolutionpi/linux/-/raw/<commit>/Makefile | sed -n 2,4p
  ```

  The two existing declarations were read that way (`576cc10` is 6.6.28, `756591ec` is
  6.12.91).
- The hash is computed from the archive Buildroot downloads
  (`https://github.com/<owner>/<repo>/archive/<commit>.tar.gz`, GitLab's
  `/-/archive/<commit>/<repo>-<commit>.tar.gz`), never taken from anywhere else: a forge
  archive's bytes cannot be derived from the git objects.

## Moving the Raspberry Pi 4 / CM4 to the 6.12 line (EI-089)

The target is the head of `raspberrypi/linux` `rpi-6.12.y`, commit
`5bd564aaa8dc4b1b8ed11733c19ec8ece63a72cc`, whose `Makefile` says Linux 6.12.114
(`git ls-remote https://github.com/raspberrypi/linux refs/heads/rpi-6.12.y`; a newer head
is a newer pin, made the same way).

**Verified without the archive.** On a blobless depth-1 fetch of exactly that commit with a
sparse checkout of the Kconfig files, `scripts/` and `arch/arm64/configs/` (16 MB, through
the git protocol):

```sh
git init . && git remote add origin https://github.com/raspberrypi/linux
git fetch --depth 1 --filter=blob:none origin 5bd564aaa8dc4b1b8ed11733c19ec8ece63a72cc
git sparse-checkout init --no-cone
printf '%s\n' /Makefile /Kconfig '**/Kconfig*' '/scripts/**' /arch/arm64/Makefile \
    '/arch/arm64/configs/**' '/arch/arm/configs/**' /Documentation/Kconfig \
    > .git/info/sparse-checkout
git checkout FETCH_HEAD
make ARCH=arm64 bcm2711_defconfig
ARCH=arm64 scripts/kconfig/merge_config.sh -m .config \
    board/suderra/aarch64-rpi4/linux-rpi4.config \
    board/suderra/aarch64-rpi4/linux-rpi4-hardening.config
make ARCH=arm64 olddefconfig
python3 scripts/ci/check-kernel-config.py resolved --defconfig suderra_aarch64_rpi4_prod_ab_defconfig \
    --kernel-tree . --config .config
```

`bcm2711_defconfig` exists at that commit, every line of both rpi4 fragments (including
`WATCHDOG_SYSFS`, `WATCHDOG_NOWAYOUT` and `BCM2835_WDT`) resolves as written, and the only
message is the stale `USER_NS` override that Buildroot's systemd fixup creates and a build
outside Buildroot does not (the same one the x86 images give). The three device trees the
defconfigs name (`broadcom/bcm2711-rpi-4-b`, `bcm2711-rpi-cm4`, `bcm2711-rpi-cm4-io`) are in
the commit's `arch/arm64/boot/dts/broadcom/Makefile`. So the bump changes no fragment.

**What is left is the hash.** The archive of that commit could not be downloaded where this
was prepared: the egress proxy denies `github.com/*/archive` and `codeload.github.com` with
HTTP 403 (a policy denial, not retried and not routed around), and the Buildroot `git`
backend would fetch every reference of the repository. Whoever can download the archive
does, in one change:

1. `curl -fL https://github.com/raspberrypi/linux/archive/5bd564aaa8dc4b1b8ed11733c19ec8ece63a72cc.tar.gz -o a.tar.gz`
   twice, compare, `sha256sum a.tar.gz`.
2. Put `# kernel-series: 6.12` and the `sha256  <hash>  linux-5bd564aaa8dc4b1b8ed11733c19ec8ece63a72cc.tar.gz`
   line in `linux.hash` in place of the `576cc10` block.
3. Change the commit in `BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION` of
   `suderra_aarch64_rpi4_defconfig`, `suderra_aarch64_rpi4_prod_ab_defconfig` and
   `suderra_aarch64_rpi4_usb_installer_defconfig`.
4. Delete the three `KNOWN_SERIES_GAPS` entries of `scripts/ci/check-kernel-config.py`
   (and the 6.6 comment above the `576cc10` block of `linux.hash` goes with the block), then
   run the `image-contracts` suite and build both rpi4 images.
5. Hardware (`docs/hardware/rpi4-cm4.md`) before a release.

## Open

- A tarball kernel has no freshness check: `scripts/ci/check-kernel-freshness.py` follows
  the kernel.org releases of the version-pinned kernels only. A branch head of a forge
  tree is the newest of its series, so the same check against `git ls-remote` is the
  natural one for the RevPi and Raspberry Pi pins.
