# Suderra OS Readiness Snapshot

Date: 2026-05-12

## Verdict

Suderra OS is not production-ready yet. It is at an integration/prototype stage:
Buildroot, systemd, multi-arch defconfigs, firewall/sysctl overlays, reproducible
build flags, and security documentation exist, but several production security
controls are still placeholders or disabled in defconfigs.

## What Is Now Wired

- `suderra-agent` from `aquaculture_platform/sens-api-gateway` has an optional
  Buildroot Cargo package, pinned to commit
  `eefc2ceb2c999d2dd444259145e10944f0b9116f`, but default defconfigs now use
  the runtime download/install flow instead of embedding the agent binary.
- The image installs `suderra-agent.service`, but it starts only after
  `/var/lib/suderra/edge/current/suderra-agent` exists.
- The provisioning flow is local console login, `/usr/sbin/suderra-edge-install`
  download + SHA256 verification, then `/usr/sbin/suderra-lockdown`.
- `/usr/sbin/suderra-lockdown-status` provides a local verification check for
  the appliance lock surface after install/reboot.
- The Buildroot Rust toolchain is lifted to Rust/Cargo 1.85.0 because the
  agent uses Rust 2024 edition and declares `rust-version = "1.85"`.
- The generated Cargo vendor archive is hash-pinned in
  `package/suderra-edge-agent/suderra-edge-agent.hash`.
- The defconfigs now use glibc plus 6.11 kernel headers so Buildroot can
  actually select systemd; before this change, the `BR2_INIT_SYSTEMD=y` lines
  were being dropped and the generated config fell back to BusyBox init.
- The runtime identity matches the Ubuntu deployment model: dedicated `suderra`
  user/group, `/etc/suderra/config.yaml`, `/var/lib/suderra`, and
  `/var/log/suderra`.
- The stale `suderra-edge-agent` placeholder unit was removed from the rootfs
  overlay so it cannot override the packaged unit.
- Appliance-mode controls disable root password login, getty/login prompts,
  `systemd-logind`, remote shell units, and rescue/debug shell units after the
  Edge install succeeds.

## Current Security Strengths

- systemd is the init system across defconfigs.
- The agent unit runs as a non-root user with `NoNewPrivileges`, syscall
  filtering, coredump disabled, strict filesystem protection, device allowlist,
  watchdog, CPU/memory/task limits, and restricted address families.
- `chrony`, `nftables`, systemd-networkd, local provisioning login, runtime
  lockdown scripts, and reproducible build flags are present in the relevant
  defconfigs.
- The agent itself uses Rust, release `panic = "abort"`, strong clippy lints,
  rustls-based networking, SQLCipher-backed state paths, and systemd notify.

## Blocking Gaps Before Production

- dm-verity, secure boot, RAUC A/B updates, TPM tooling, and TPM-backed key
  storage are documented but disabled or incomplete in the OS defconfigs.
- The existing firstboot path is still an inline shell bootstrap. The Rust
  `suderra-firstboot` package exists but is not the active firstboot owner.
- No QEMU boot evidence has been captured after enabling the real agent package.
- The full provisioning flow has not yet been boot-tested: login, artifact
  download, SHA256 verification, service start, lockdown, reboot, and failed
  login attempts.
- No `systemd-analyze security suderra-agent` result exists from a built image.
- The agent's upstream Ubuntu runbook has a config ownership/read-write mismatch:
  root-owned `0600` config plus read-only `/etc/suderra` conflicts with a
  non-root service that must read and later save `config.yaml`. The OS unit
  currently permits `/etc/suderra` writes so provisioning can work.
- The upstream `agent-v1.6.0` tag currently has a stale `Cargo.lock` relative to
  its `Cargo.toml`; Suderra OS therefore pins a verified commit SHA instead of
  that tag.
- Release signing/SBOM/VEX docs exist, but the release pipeline evidence has not
  been verified in this workspace.
- SHA256-only artifact verification is an interim bootstrap control. Production
  must require an offline-trusted release signature or equivalent verified
  transparency-log flow before the installer accepts an Edge artifact.

## Practical Readiness Level

- Lab/QEMU: possible after build verification.
- Pilot hardware: not yet; needs first boot, service start, provisioning, and
  network/firewall validation on target hardware.
- Production: no; blocked by verified secure boot, dm-verity, RAUC rollback,
  TPM/keystore policy, release signing, and end-to-end boot tests.

## Next Gates

1. Build `suderra_qemu_x86_64_defconfig`.
2. Boot it in QEMU and confirm provisioning login appears.
3. Install a test `suderra-agent` artifact with `/usr/sbin/suderra-edge-install`.
4. Confirm `suderra-agent.service` reaches active or a controlled provisioning
   wait state.
5. Confirm appliance lockdown after reboot: no getty prompt, no root login, no
   SSH/dropbear, `suderra-lockdown-status` passes, and only allowlisted services
   active.
6. Run `systemd-analyze security suderra-agent` inside the image.
7. Fix firstboot ownership into Rust or a tested shell unit with explicit tests.
8. Enable and validate dm-verity + RAUC + secure boot on one target class.
