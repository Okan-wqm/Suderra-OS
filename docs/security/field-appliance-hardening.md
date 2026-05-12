# Field Appliance Hardening Model

Date: 2026-05-12

## Goal

Suderra OS must not behave like a general-purpose Ubuntu host in the field. It
uses a short provisioning window only to install Suderra Edge. After that, the
device is locked into appliance mode: no human login, no remote shell, no debug
shell, and no non-Suderra application service.

## Current Flow

1. Install and boot Suderra OS.
2. Local console and temporary SSH are available only for provisioning:
   `root` / `suderra`.
3. The operator connects by IP during provisioning and uses the tenant panel
   Edge download link to populate `/etc/suderra/edge-install.env`.
4. `/root/.profile` starts `/usr/sbin/suderra-edge-install` when the Edge binary
   is missing, or the operator runs it manually over SSH.
5. The installer downloads the configured Edge artifact, verifies SHA256, places
   the binary at `/var/lib/suderra/edge/current/suderra-agent`, enables
   `suderra-agent.service`, and runs `/usr/sbin/suderra-lockdown`.
6. Lockdown disables root password login, getty, debug/rescue/emergency shell,
   ssh/dropbear units, `systemd-logind`, and reloads the appliance firewall.
7. After reboot, the expected runtime surface is mandatory base services,
   nftables, network/time, and `suderra-agent.service`.

## Implemented Controls

| Area | Control |
|---|---|
| Identity | Edge runs as non-root `suderra` UID/GID 200 |
| Service sandbox | `NoNewPrivileges`, strict filesystem protection, syscall filter, device allowlist |
| Login surface | Root password, getty, and temporary SSH are disabled after install |
| Remote shell | dropbear is available only in provisioning and masked by lockdown |
| Firewall | provisioning firewall allows SSH; appliance firewall has default-drop inbound |
| Kernel runtime | sysctl hardening for ptrace, dmesg, BPF, kexec, redirects, source route |
| Artifact bootstrap | Installer requires SHA256 before installing |
| Update contract | Edge changes that affect OS paths, devices, capabilities, ports, config schema, or Rust version are documented |

## Production Gates

These are not optional for real field deployment:

1. Secure Boot or measured boot must verify bootloader, kernel, initramfs, and
   rootfs trust chain.
2. dm-verity must make the root filesystem read-only and tamper-evident.
3. RAUC A/B updates must provide signed OS updates and rollback.
4. Edge artifacts must be signed. SHA256 alone is accepted only for lab
   bootstrap because an attacker who can replace both artifact and hash can win.
5. TPM-backed identity/key storage must replace filesystem-only secret storage
   on hardware that supports TPM.
6. nftables outbound rules must move from protocol-only allowlist to production
   endpoint policy once cloud endpoints and broker addresses are final.
7. A built image must pass QEMU and target-hardware boot tests, including
   install, reboot, failed login attempts, firewall checks, and
   `systemd-analyze security suderra-agent.service`.
8. Release output must include SBOM, VEX when needed, CVE scan evidence, and a
   reproducible build checksum.

## Edge Update Contract

When Suderra Edge changes, update Suderra OS only if one of these contracts
changes:

| Edge change | OS update point |
|---|---|
| Binary name or artifact format | `/etc/suderra/edge-install.env` |
| Runtime path | `suderra-agent.service` |
| Config schema | `suderra-firstboot.service` and default config templates |
| Required device node | `DeviceAllow=` in `suderra-agent.service` |
| Required Linux capability | `CapabilityBoundingSet=` / `AmbientCapabilities=` |
| Writable directory | `ReadWritePaths=` and firstboot directory setup |
| New outbound protocol/port | `etc/nftables.conf` |
| New minimum Rust version | Buildroot Rust toolchain and optional embedded package |

## Field Acceptance Check

After provisioning and one reboot, the image is not field-acceptable unless all
of these pass:

```bash
/usr/sbin/suderra-lockdown-status
systemctl is-enabled suderra-agent.service
systemctl status suderra-agent.service
nft list ruleset
```

Expected external behavior:

- No SSH/dropbear listener after lockdown.
- No successful root password login.
- No getty prompt after appliance reboot.
- No inbound network service except explicitly approved future services.
- Edge data and logs exist only under `/etc/suderra`, `/var/lib/suderra`, and
  `/var/log/suderra`.

## Current Security Level

Current state is suitable for integration and lab validation, not final
production deployment. The biggest remaining risks are unsigned Edge artifacts,
missing verified boot/dm-verity/RAUC enforcement, endpoint-level outbound
allowlisting, and lack of captured boot-test evidence on target hardware.
