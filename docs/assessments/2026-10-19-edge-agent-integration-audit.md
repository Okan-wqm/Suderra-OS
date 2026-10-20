# 2026-10-19 — Edge agent entegrasyon denetimi (Suderra OS tarafı)

**Durum:** active · **Karar kaydı:** [ADR-0008](../architecture/ADR-0008-edge-agent-integration-contract.md) → aquaculture_platform ADR-048. Platform (agent, bulut, CI) tarafındaki bulgular aquaculture_platform reposunda `docs/reviews/claude/2026-10-19-suderra-os-edge-integration-audit.md` içindedir.

Bu repodaki kapatan commit'ler `Refs: docs/assessments/2026-10-19-edge-agent-integration-audit.md#EI-NNN` satırını taşır.

## Yöntem

1. Dört bağımsız envanter taraması (gateway saldırı yüzeyi, gateway iç yapısı, Suderra OS, entegrasyon + bulut).
2. 126 iddia yedi alanda kodla tek tek doğrulandı (`file:line` kanıtı zorunlu; kanıt yoksa REFUTED/UNVERIFIABLE).
3. CRITICAL/HIGH çıkan her iddia ayrı bir şüpheci agent tarafından çürütülmeye çalışıldı (78 iddia; hiçbiri
   çürütülemedi, bir kısmının önemi yeniden derecelendirildi — bkz. Not satırları).
4. Kod okunurken kaydedilen 174 yan bulgu tekilleştirildi (iddialarla çakışanlar ilgili iddiaya kanıt olarak eklendi).
5. Kritik iddiaların bir bölümü ayrıca elle doğrulandı (config yolu, `sd_notify(true)` → `NOTIFY_SOCKET` silinmesi —
   sd-notify 0.4.5 kaynağı, provision-worker `ReadWritePaths`, `/data` bind-mount'ları, RAUC health gate, lockdown
   marker'ı, release feature seti, bulut komut imzalayıcısının bağlantısızlığı, tarball binary adı).

Fazlar ve son tarihler ADR-048'in uygulama planından gelir: P0 2026-11-02, P1 2026-11-30, P2 2026-12-31,
P3 2027-03-31. Yan bulgular, uygulama paketine alınana kadar önemine göre P1 (CRITICAL/HIGH) veya P2'ye yazıldı.

## Özet

| Phase | CRITICAL | HIGH | MEDIUM | LOW | Toplam |
|---|---|---|---|---|---|
| P0 | 9 | 8 | 6 | 2 | 25 |
| P1 | 6 | 17 | 9 | 1 | 33 |
| P2 | 0 | 0 | 16 | 13 | 29 |

## Dizin

| ID | Önem | Faz | Başlık |
|---|---|---|---|
| [EI-001](#EI-001) | CRITICAL | P0 | Worker sandbox makes the installer's state and work directories read-only, so every install aborts at the first mkdir |
| [EI-002](#EI-002) | CRITICAL | P0 | Spool parent directory is root:root 0750, so the provision user cannot reach its inbox or read its result |
| [EI-003](#EI-003) | CRITICAL | P0 | Forced-command login shell is not in /etc/shells, so dropbear rejects every provision login |
| [EI-004](#EI-004) | CRITICAL | P0 | Lockdown requires a registration marker that nothing ever writes, so every install rolls back |
| [EI-005](#EI-005) | CRITICAL | P0 | `sed -i /etc/shadow` cannot work when only the shadow file is writable, so lockdown aborts under set -e |
| [EI-006](#EI-006) | CRITICAL | P0 | Three writers disagree on who owns /var/lib/suderra; after install it is root:root 0750 and the agent (uid 200) cannot reach its own state |
| [EI-007](#EI-007) | CRITICAL | P0 | Production images can neither embed nor install the agent |
| [EI-008](#EI-008) | CRITICAL | P0 | RAUC health gate fails whenever the agent unit file exists but the agent is not running (always true on prod), and skips the declared verity/LUKS/rollback-floor checks |
| [EI-009](#EI-009) | CRITICAL | P0 | x86_64 kernel has no initramfs support, so the UKI's verity initramfs is ignored and root=/dev/mapper/suderra-root never appears |
| [EI-010](#EI-010) | CRITICAL | P1 | suderra-data.service cannot start because its ReadWritePaths name directories absent from the rootfs (226/NAMESPACE), and even if it started, the /data and bind mounts it makes stay inside its private mount namespace |
| [EI-011](#EI-011) | CRITICAL | P1 | systemd pre-expands the inline firstboot shell: ${pass}/${hash} become empty and %s becomes /bin/sh, so the provision account gets an empty shadow field, credentials.env and the console show "/bin/sh", and the config skeleton is written as repeated "/bin/sh" lines |
| [EI-012](#EI-012) | CRITICAL | P1 | suderra-rauc-mark-good rolls back (mark-bad + reboot) on every normal boot without a pending OTA, because `suderra-ota mark-good` errors "no pending version to mark good" and its failure triggers rollback |
| [EI-013](#EI-013) | CRITICAL | P1 | FIT signature never enforced on Pi: keyed u-boot.dtb is not U-Boot's control FDT, and verity/lockdown bootargs never reach the kernel |
| [EI-014](#EI-014) | CRITICAL | P1 | GRUB never marks a slot as being tried, so a slot that fails before userspace boot-loops forever with no fallback |
| [EI-015](#EI-015) | HIGH | P0 | Provisioning credential is a console-printed shared password stored in plaintext, and openssl (needed to hash it) is missing on two dev images |
| [EI-016](#EI-016) | HIGH | P0 | Cloud sends the provisioning token as an extra SSH argument, which the device drops; the manifest fetch has no token and gets 401 |
| [EI-017](#EI-017) | HIGH | P0 | Release layout is split between the read-only, per-slot rootfs (current link) and /data (releases), and the bind mounts hide the package's own outputs |
| [EI-018](#EI-018) | HIGH | P0 | Board detection has no x86 branch (exits 2), and on RevPi Connect 4 it will report rpi4-cm4 |
| [EI-019](#EI-019) | HIGH | P0 | Agent user has no device groups and the OS ships no udev rules, so DeviceAllow alone cannot grant field I/O |
| [EI-020](#EI-020) | HIGH | P0 | x86_64 production kernel has no dm-crypt, so LUKS2 /data cannot be formatted or opened |
| [EI-021](#EI-021) | HIGH | P0 | x86_64 kernel lacks conntrack/ct/limit, so the nftables ruleset fails to load and boot continues with no firewall |
| [EI-022](#EI-022) | HIGH | P1 | RPi4/RevPi dev and RPi USB-installer images boot with root=LABEL= and no initramfs; the kernel cannot resolve LABEL=, so boot hangs on rootwait |
| [EI-023](#EI-023) | HIGH | P1 | The qemu x86_64 and generic aarch64 dev images ship the provisioning units without suderra-installer or the pinned edge key, so suderra-edge-install exits 2 for every manifest |
| [EI-024](#EI-024) | HIGH | P1 | ARM prod boots the raw kernel DTB embedded in the signed FIT, so config.txt dtparam/dtoverlay (I2C, SPI, watchdog, disable-bt UART routing, TPM, RevPi) are silently dropped in production |
| [EI-025](#EI-025) | HIGH | P1 | Lockdown deletes the provisioning spool and runs `systemctl stop suderra-provision-worker.service` from inside that unit, killing edge-install and itself before current.env (the downgrade guard) and the install result are written |
| [EI-026](#EI-026) | HIGH | P1 | Prod images mount a read-only dm-verity root but keep Buildroot REMOUNT_ROOTFS_RW=y, so fstab says rw, no /var tmpfs/factory/overlay exists, and all /var state (installer state, spool, chrony drift, journal) is read-only |
| [EI-027](#EI-027) | HIGH | P1 | The QEMU runtime-scenario driver calls suderra-ota with an invalid CLI and scores any failure as the expected rejection, so OTA, bad-signature and anti-rollback evidence is vacuous |
| [EI-028](#EI-028) | HIGH | P1 | x86_64 kernels are pinned to 6.12.6, about 45 stable releases behind the 6.12.51 that Buildroot hashes and the toolchain headers track |
| [EI-029](#EI-029) | HIGH | P1 | ARM prod has no usable TPM device, so /data provisioning fails closed on every RPi4/CM4/RevPi prod device |
| [EI-030](#EI-030) | HIGH | P1 | suderra-ota never runs in production mode, and its target defaults to x86_64, so every ARM OTA manifest is rejected |
| [EI-031](#EI-031) | HIGH | P1 | Anti-rollback exists only in the suderra-ota wrapper; rauc install (CLI/D-Bus) bypasses the floor |
| [EI-032](#EI-032) | HIGH | P1 | RevPi images are generic CM4 images: no KUNBUS kernel, piControl or RevPi device tree, so PiBridge I/O, RS485 and LEDs are unusable |
| [EI-033](#EI-033) | HIGH | P1 | Hardware watchdog is enabled in firmware and kernel, but nothing opens or feeds it, so there is no hang recovery |
| [EI-034](#EI-034) | HIGH | P1 | U-Boot environment is a plain file on a permanently rw-mounted FAT with no variable allow-list |
| [EI-035](#EI-035) | HIGH | P1 | FIT signature enforcement covers only bootm; bootefi/booti/sysboot/PXE/DHCP/USB boot and an interruptible console remain |
| [EI-036](#EI-036) | HIGH | P1 | Production boot.scr is an unsigned legacy script image on a writable FAT, and U-Boot cannot even run it |
| [EI-037](#EI-037) | HIGH | P1 | /data key is sealed to PCR7 only, with no PIN or recovery path; on ARM PCR7 is never measured, so any OS booted on the device can unseal it |
| [EI-038](#EI-038) | MEDIUM | P0 | Signed edge manifest is not bound to the device, so it can be replayed (including its config and identity) to any device of the same board/arch |
| [EI-039](#EI-039) | MEDIUM | P0 | Agent anti-rollback guard sits on rootfs, is bypassable by an unsigned env var, and uses version ordering that differs from the verifier's |
| [EI-040](#EI-040) | MEDIUM | P0 | Lockdown is an optional env knob; skipping it still reports a successful install |
| [EI-041](#EI-041) | MEDIUM | P0 | Lock state is a marker file on mutable, agent-owned storage that picks the firewall profile; prod never creates it and keeps 22/tcp open |
| [EI-042](#EI-042) | MEDIUM | P0 | Three diverging copies of suderra-agent.service; the untested overlay copy is the effective one and grants /dev/watchdog |
| [EI-043](#EI-043) | MEDIUM | P0 | x86_64 industrial kernel has no USB host, USB-serial, I2C/SMBus or GPIO drivers and no microcode delivery |
| [EI-044](#EI-044) | MEDIUM | P1 | /data unlock failure is silent: boot continues, the agent condition-skips, and dev mounts /data by a spoofable label |
| [EI-045](#EI-045) | MEDIUM | P1 | RPi4/CM4 and RevPi Connect 4 share RAUC compatible=suderra-os-aarch64 |
| [EI-046](#EI-046) | MEDIUM | P1 | Nothing gates time-sync.target, there is no RTC, and time-dependent security runs on the build-epoch clock until NTP |
| [EI-047](#EI-047) | MEDIUM | P1 | No defined procedure to take Secure Boot ownership (PK/KEK/db) on Windows-shipped industrial PCs; GRUB is signed only with the Suderra db key and there is no shim |
| [EI-048](#EI-048) | MEDIUM | P1 | ARM kernel loads modules without enforced signatures and lockdown is not forced |
| [EI-049](#EI-049) | MEDIUM | P1 | ARM cmdline lacks module.sig_enforce/debugfs=off and the kernel/firmware/U-Boot console shares ttyAMA0 with Modbus-RTU |
| [EI-050](#EI-050) | MEDIUM | P1 | dm-verity table has no corruption policy, and partitions are taken from the first PARTLABEL match |
| [EI-051](#EI-051) | MEDIUM | P1 | x86 kernel tarball (6.12.6) is not hash-enforced; forced hash checking is enabled only on ARM defconfigs |
| [EI-052](#EI-052) | MEDIUM | P2 | chrony is built without NTS and ships the example config (pool.ntp.org, makestep 1.0 3, drift on read-only /var), while the agent's ChronyNtsClockAuthority assumes NTS |
| [EI-053](#EI-053) | MEDIUM | P2 | The installer resolves its cosign verifier from COSIGN_BINARY or PATH with no production lock, cosign is not shipped, and the error text suggests curl-installing "latest" |
| [EI-054](#EI-054) | MEDIUM | P2 | The signed edge manifest is canonicalized by re-serializing the parsed Rust struct (unknown fields dropped unsigned, chrono re-formatting), and verification uses non-strict Ed25519 verify |
| [EI-055](#EI-055) | MEDIUM | P2 | Install rollback restores only the current link: config.yaml is overwritten before activation and never restored, and a failed first install leaves the new agent enabled |
| [EI-056](#EI-056) | MEDIUM | P2 | Kernel hardening intent is silently overridden by Buildroot fixups: systemd forces CONFIG_USER_NS=y despite both fragments disabling it, and CONFIG_GCC_PLUGIN_STACKLEAK is dropped because Buildroot disables GCC_PLUGINS |
| [EI-057](#EI-057) | MEDIUM | P2 | Spool IPC race: the worker fires on any inbox change and can claim a manifest still being streamed from SSH stdin, so verification fails intermittently |
| [EI-058](#EI-058) | MEDIUM | P2 | The root-password guardrail treats an empty shadow field (passwordless login) as "locked — safe", and checks only root |
| [EI-059](#EI-059) | MEDIUM | P2 | Egress open on fixed ports to any destination, no DHCP rule, and agent protocols blocked; static rules cannot be customised per site |
| [EI-060](#EI-060) | MEDIUM | P2 | Published release images are dev variants with ephemeral CI trust roots |
| [EI-061](#EI-061) | MEDIUM | P2 | Installer verifies the payload, then re-reads it from removable media (TOCTOU); a failed post-write check leaves the unverified image bootable |
| [EI-062](#EI-062) | MEDIUM | P2 | Installer security escapes (TLS off, legacy copy install) are gated by a variant check that the environment can override |
| [EI-063](#EI-063) | LOW | P0 | The firstboot config skeleton uses the all-zero UUID, which fails @IsUUID('4', ...); in the designed flow that request is never sent |
| [EI-064](#EI-064) | LOW | P0 | Manifest version is used unvalidated as a filesystem path component and symlink target |
| [EI-065](#EI-065) | LOW | P1 | Fragment sets nonexistent CONFIG_SPIDEV instead of CONFIG_SPI_SPIDEV |
| [EI-066](#EI-066) | LOW | P2 | Two suderra-firstboot.service definitions exist; the overlay inline-shell unit in /etc shadows the packaged Rust one, whose advertised TPM/registration/mark-good behaviour never runs |
| [EI-067](#EI-067) | LOW | P2 | grubenv on the unauthenticated ESP lets a disk-level attacker select any validly signed slot, including an older image in the other slot |
| [EI-068](#EI-068) | LOW | P2 | The verity initramfs copies the entire /lib, /lib64 and /usr/lib (52 MB on the x86 dev target) into every signed boot artifact |
| [EI-069](#EI-069) | LOW | P2 | The Buildroot agent package builds default features only (no scada-display, opc-ua-server or gpio) from a different pinned commit than the release, while its help text advertises OPC UA and SCADA |
| [EI-070](#EI-070) | LOW | P2 | Suderra OS operator output and docs reference a non-existent unit (suderra-edge-agent.service), a root/suderra login and an agent path (/var/lib/suderra/edge/current) that the code contradicts |
| [EI-071](#EI-071) | LOW | P2 | suderra-ota-mark-good.service is installed but never enabled, and would mark the slot good without the health gate |
| [EI-072](#EI-072) | LOW | P2 | install-manifest-json copies unbounded stdin into the persistent spool |
| [EI-073](#EI-073) | LOW | P2 | system.conf.arm registers the slot hook as a system post-install handler, where RAUC_SLOT_CLASS is absent, making it a silent no-op |
| [EI-074](#EI-074) | LOW | P2 | sysctl hardening omits modules_disabled, ldisc_autoload, unprivileged_userfaultfd, bpf_jit_harden and io_uring_disabled |
| [EI-075](#EI-075) | LOW | P2 | post-build strips setuid but not setgid bits, contrary to its whitelist comment |
| [EI-076](#EI-076) | MEDIUM | P1 | The USB self-installer takes its payload key, verifier, rollback floor, key epoch, target board and confirmation from SUDERRA_INSTALLER_* environment variables |
| [EI-077](#EI-077) | HIGH | P0 | systemd is built without seccomp on every image, so every unit's SystemCallFilter=, RestrictAddressFamilies=, MemoryDenyWriteExecute=, LockPersonality=, RestrictRealtime= and SystemCallArchitectures= are dropped, the agent's included |
| [EI-078](#EI-078) | CRITICAL | P1 | No image selects e2fsprogs, so production first-boot /data provisioning dies at mkfs.ext4 after the LUKS volume is already formatted and TPM-sealed, and no image has fsck.ext4 |
| [EI-079](#EI-079) | HIGH | P1 | Suderra OS userspace/Cargo.lock pins rustls 0.23.40 (four RUSTSEC TLS advisories) and the unmaintained unsafe-libyaml via serde_yaml, so cargo deny, Trivy and Grype fail on main and the root installer/ota/telemetry TLS clients carry known flaws |
| [EI-080](#EI-080) | MEDIUM | P2 | The OS update manifest and the USB payload index are signed over a re-serialized struct, verified with non-strict Ed25519 verify, and accept unknown fields; the Python signer matches Rust only by dict order |
| [EI-081](#EI-081) | MEDIUM | P2 | suderra-ota writes its state file with write+rename and no fsync, and the rollback-floor file without a directory fsync, so a power cut during an update can leave empty state or lose the floor |
| [EI-082](#EI-082) | MEDIUM | P2 | suderra-ota checks the bundle's digest and size, then lets rauc install re-read the file by path, so a bundle swapped in between (removable media) bypasses the manifest and rollback-floor check |
| [EI-083](#EI-083) | LOW | P2 | The rpi4 and revpi4 dev genimage data.ext4 has no 'empty = true', so genimage fills the SUDERRA-DATA partition with a copy of the whole target rootfs |
| [EI-084](#EI-084) | MEDIUM | P2 | suderra-lockdown reports failures with reasons the lockdown result schema forbids (lifecycle-inconsistent, state-corrupt), so those failure paths record no result |
| [EI-085](#EI-085) | MEDIUM | P2 | The QEMU semantic evidence collector fails on every boot: ProtectSystem=strict leaves /run read-only and the unit declares no RuntimeDirectory |
| [EI-086](#EI-086) | LOW | P2 | The QEMU dev image sets BR2_PACKAGE_SYSTEMD_RESOLVED=n while /etc/resolv.conf points at ../run/resolv.conf, which nothing writes, so the image cannot resolve names |
| [EI-087](#EI-087) | LOW | P2 | OS config and doc hygiene: kernel-hardening.md and ota.md name removed or old symbols, dead BR2 symbols in the QEMU defconfig, an unneeded CONFIG_TCG_VTPM_PROXY in the x86 kernel, and a build-order versus Kconfig inversion for suderra-ota |

## Bulgular

<a id="EI-001"></a>

### EI-001 — Worker sandbox makes the installer's state and work directories read-only, so every install aborts at the first mkdir

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** rootfs-overlay: suderra-provision-worker.service / suderra-edge-install
- **Köken:** doğrulanan iddia T65 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-provision-worker.service:22-23`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:5`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-provision-worker.service:22-23 ProtectSystem=strict; ReadWritePaths=/var/spool/suderra-provision /var/lib/suderra /var/log/suderra /opt/suderra /etc/suderra /etc/systemd/system /etc/shadow (no /var/lib/suderra-installer, no /run/suderra-installer, no RuntimeDirectory/StateDirectory)
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:5 STATE_DIR=/var/lib/suderra-installer/edge, :7 WORK_DIR=/run/suderra-installer/edge, :142 mkdir -p "${STATE_DIR}" "${WORK_DIR}" ... under set -eu (:2)
  - systemd 256.17 (Buildroot pin) src/core/namespace.c:213-221 protect_system_strict_table: '/' MOUNT_READ_ONLY; only /proc,/sys,/dev,/home,/run/user,/root are implicitly writable, so /run and /var/lib are read-only
  - Nothing in the tree creates /var/lib/suderra-installer or /run/suderra-installer (grep of board/ package/ shows no tmpfiles.d or mkdir for them)
  - Second blocker in the same unit: ReadWritePaths=/opt/suderra, but /opt is empty in the built rootfs (debugfs of output/suderra_qemu_x86_64_defconfig/images/rootfs.ext2), and namespace.c:1556-1566 fails with -ENOENT for a non-'-'-prefixed path, so the worker cannot even start (226/NAMESPACE)
- **Kök neden:** The writable set of the sandbox is a hand-written list kept apart from the paths the scripts actually write. ProtectSystem=strict was added without using systemd's own StateDirectory=/RuntimeDirectory= facilities, and no test runs edge-install inside the real unit sandbox.
- **Mimari düzeltme yönü:** Have systemd own the directories. Declare StateDirectory=suderra-installer and RuntimeDirectory=suderra-installer (or point state at the /data persistent store through a declared mount) in the worker unit, and make suderra-edge-install read $STATE_DIRECTORY/$RUNTIME_DIRECTORY rather than hard-coded paths, so the sandbox and the script cannot diverge. Every ReadWritePaths entry must exist by construction: create it in tmpfiles.d, or prefix it with '-' only where it is truly optional.
- **Doğrulama:** Add a CI/QEMU test that runs suderra-edge-install with a signed fixture manifest via `systemd-run --wait` using the exact properties of the worker unit, or via the real path trigger, and asserts exit 0. Add a static contract test that every absolute path the scripts write is covered by the unit's StateDirectory/RuntimeDirectory/ReadWritePaths.

<a id="EI-002"></a>

### EI-002 — Spool parent directory is root:root 0750, so the provision user cannot reach its inbox or read its result

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** rootfs-overlay: suderra-firstboot.service / suderra-provision
- **Köken:** doğrulanan iddia T66 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:42`, `board/suderra/common/users.txt:30`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:39`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision-worker:6`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:42 chown root:root /var/lib/suderra /var/spool/suderra-provision; :47 chmod 0750 /var/spool/suderra-provision; :44,:48 inbox 201:201 0700
  - board/suderra/common/users.txt:30 provision uid 201, home /var/spool/suderra-provision
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:39 mkdir -p "${REQUEST_DIR}" fails with EACCES (uid 201 has no search permission on the 0750 root:root parent) and set -eu (:2) exits; :40 rm -f result, :48 write to inbox and :65-66 read of result are also impossible
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision-worker:6,18-20 the result is written into the same root-owned BASE_DIR
  - Latent follow-on bug: even with the parent made traversable, suderra-provision:40 `rm -f result` cannot unlink a file in a root-owned directory, so every attempt after the first exits early
- **Kök neden:** Ownership and modes of the IPC spool are set ad hoc by inline shell in firstboot, apart from the users table and from the scripts that use the spool. The file-based IPC protocol has no single declared permission contract.
- **Mimari düzeltme yönü:** Declare the spool layout once in tmpfiles.d, e.g. `d /var/spool/suderra-provision 0711 root root`, inbox 0700 provision and a provision-owned outbox for results that the worker writes into, and remove the chown/chmod lines from firstboot. Better still, replace the spool and polling design with a socket-activated root service (AF_UNIX, peer credentials checked by SO_PEERCRED) whose reply goes back on the same connection. That removes shared-directory permission problems entirely.
- **Doğrulama:** Run suderra-provision as uid 201 against the tmpfiles-created tree in a container or QEMU and assert that the request is accepted and the result is read. Run the QEMU provisioning e2e twice to cover the second-run rm path.

<a id="EI-003"></a>

### EI-003 — Forced-command login shell is not in /etc/shells, so dropbear rejects every provision login

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** users.txt / /etc/shells / dropbear
- **Köken:** doğrulanan iddia T67 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/users.txt:30`
- **Kanıt (ayrıntı):**
  - board/suderra/common/users.txt:30 provision shell /usr/sbin/suderra-provision
  - Built image output/suderra_qemu_x86_64_defconfig/images/rootfs.ext2 /etc/shells (debugfs) contains only /bin/ash and /bin/sh
  - buildroot/package/skeleton-init-common/skeleton-init-common.mk:88-92 and package/busybox/busybox.mk:402-413 add only /bin/sh, /bin/ash and /bin/hush; nothing in board/ or package/ appends suderra-provision
  - dropbear 2025.88 (Buildroot pin) src/svr-auth.c:313-334 walks getusershell(); with no match it logs "User '%s' has invalid shell, rejected" and returns DROPBEAR_FAILURE
- **Kök neden:** The design relies on a login-shell trick for the forced command, but Buildroot registers only shells it builds itself. No image-level check compares the passwd shells with /etc/shells.
- **Mimari düzeltme yönü:** Use dropbear's native forced command, an authorized_keys `command="/usr/sbin/suderra-provision",no-pty,no-port-forwarding` entry with key auth, and give the account /sbin/nologin. If a login shell is kept, generate /etc/shells from the users table in post-build. In both cases add a build-time assertion that every interactive passwd shell is listed in /etc/shells.
- **Doğrulama:** An image contract test reads /etc/passwd and /etc/shells from the final rootfs (debugfs) and fails on mismatch. A QEMU test checks that `ssh provision@guest install-manifest-url ...` reaches suderra-provision.

<a id="EI-004"></a>

### EI-004 — Lockdown requires a registration marker that nothing ever writes, so every install rolls back

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-lockdown / suderra-edge-install
- **Köken:** doğrulanan iddia T70 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:41-43`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:303-313`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:41-43 fails unless /var/lib/suderra/edge/registered or /var/lib/suderra/registration.json exists
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:303-313 calls lockdown right after restart; on failure it restores or removes the current link and exits 1
  - grep of aquaculture_platform/sens-api-gateway/src finds no write of either marker (provisioning.rs has activate/self_register but no persistence of a registered marker); grep of Suderra-OS finds the paths only in suderra-lockdown
  - Lockdown runs immediately after `systemctl restart`, with no wait for the asynchronous cloud activation, so it would race even if a producer existed
- **Kök neden:** The cross-repo contract (the agent signals successful registration and the OS locks down) was assumed but never specified or implemented. No shared constant or test ties the producer to the consumer.
- **Mimari düzeltme yönü:** Specify the registration-state contract in both repos: path, schema and atomic write by the agent after successful activation, including device_id, which lockdown checks against the manifest's device_id. Or use an sd_notify STATUS / local socket readiness signal. Lockdown waits on it with a bounded timeout. The path constant comes from one shared definition.
- **Doğrulama:** Agent integration test with a mocked cloud asserts the marker is written atomically after activation. OS e2e test in QEMU: provision, observe the marker, lockdown succeeds, and lockdown-status reports OK.

<a id="EI-005"></a>

### EI-005 — `sed -i /etc/shadow` cannot work when only the shadow file is writable, so lockdown aborts under set -e

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-lockdown (inside suderra-provision-worker sandbox)
- **Köken:** doğrulanan iddia T71 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:2`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-provision-worker.service:22-23`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:2 set -eu; :52-60 lock_user runs `passwd -l ... || true` then `sed -i "s#^${user}:[^:]*:#${user}:!:#" /etc/shadow`; :62-63
  - suderra-provision-worker.service:22-23 ProtectSystem=strict with only the file /etc/shadow in ReadWritePaths (bind-mounted single file); /etc itself stays read-only
  - busybox 1.37.0 editors/sed.c:1641-1642 xmkstemp("<file>XXXXXX") creates the temp file in /etc (EROFS) and :1665 xrename onto the bind-mounted file (EBUSY); libbb/update_passwd.c:121,319 (used by passwd -l) has the same "/etc/shadow+" plus rename pattern
  - Lockdown runs in the worker's mount namespace because edge-install is a child of the worker (suderra-provision-worker:51/59 -> edge-install:304)
- **Kök neden:** Account locking edits the system password database with in-place text tools, which need a writable parent directory and a rename. The sandbox was narrowed to a single file without exercising lockdown inside it.
- **Mimari düzeltme yönü:** Stop mutating /etc/shadow at runtime. Ship root and provision locked at build time (already '!'), grant provisioning access only through a revocable key file in a writable state directory (dropbear -D or authorized_keys under /var/lib/suderra-provision), and let lockdown revoke access by deleting that file and masking units. This makes the failure mode impossible rather than widening the sandbox to /etc.
- **Doğrulama:** Run suderra-lockdown under `systemd-run` with the worker's exact sandbox properties in QEMU and assert exit 0. A contract test rejects `sed -i` and `passwd` invocations on /etc files in any script executed by a sandboxed unit.

<a id="EI-006"></a>

### EI-006 — Three writers disagree on who owns /var/lib/suderra; after install it is root:root 0750 and the agent (uid 200) cannot reach its own state

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install / suderra-firstboot.service / suderra-data-unlock
- **Köken:** doğrulanan iddia T72 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:143`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:42`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:21-22`, `package/suderra-edge-agent/suderra-edge-agent.mk:49`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:12`, `board/suderra/common/users.txt:26`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:143 chmod 0750 /var/lib/suderra; :145 chown root:root /var/lib/suderra; then :290-300 restarts the agent and rolls back if it is not active
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:42,46 chown root:root and chmod 0750 /var/lib/suderra
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:21-22,24 chowns the bind-mounted /var/lib/suderra to root:root, then /data/suderra/lib (same inode) to 200:200, mode 0750
  - package/suderra-edge-agent/suderra-edge-agent.mk:49 declares /var/lib/suderra as 750 suderra:suderra
  - rootfs-overlay/etc/systemd/system/suderra-agent.service:12,18 User=suderra reads SUDERRA_CONFIG=/var/lib/suderra/config/config.yaml; with a root:root 0750 parent, open() returns EACCES, the agent exits, restart fails and edge-install:292-300 rolls back
  - users.txt:26 suderra has no supplementary groups, so group root access is not available either
- **Kök neden:** There is no single source of truth for filesystem ownership. firstboot, edge-install, data-unlock and the Buildroot permission table each chown the same directory to different owners. Which one wins depends on boot and install order.
- **Mimari düzeltme yönü:** Declare ownership once: a tmpfiles.d entry `d /var/lib/suderra 0750 suderra suderra` (or StateDirectory=suderra in the agent unit, so systemd enforces the owner on every start), and delete every ad-hoc chown/chmod of /var/lib/suderra from the scripts. Root-only installer state lives in its own directory (see T65).
- **Doğrulama:** Contract test: grep fails if any script chowns or chmods /var/lib/suderra outside tmpfiles. QEMU test: stat /var/lib/suderra after first boot, after install and after reboot, and assert 200:200 0750 every time with the agent active.

<a id="EI-007"></a>

### EI-007 — Production images can neither embed nor install the agent

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** post-build.sh prod path / package/suderra-edge-agent Kconfig
- **Köken:** doğrulanan iddia T80 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/post-build.sh:188-189`, `board/suderra/common/post-build.sh:228-286`, `package/suderra-edge-agent/Config.in:1-7`, `configs/suderra_aarch64_revpi4_prod_ab_defconfig:118`, `configs/suderra_x86_64_defconfig:21`, `board/suderra/common/post-build.sh:228-265`, `board/suderra/common/post-build.sh:222-227`, `package/suderra-edge-agent/suderra-edge-agent.mk:17`
- **Kanıt (ayrıntı):**
  - board/suderra/common/post-build.sh:188-189 prod enables only suderra-agent.service; firstboot, dropbear and the provision path are enabled only for dev (:190-198)
  - post-build.sh:228-286 prod masks dropbear, suderra-provision-worker.path/.service, getty and rescue, and locks provision
  - package/suderra-edge-agent/Config.in:1-7 BR2_PACKAGE_SUDERRA_EDGE_AGENT depends on a promptless `bool` (CARGO4_HASH_REVALIDATED, default n) that nothing selects, so the package cannot be enabled; every defconfig has '# BR2_PACKAGE_SUDERRA_EDGE_AGENT is not set' (e.g. configs/suderra_aarch64_revpi4_prod_ab_defconfig:118, suderra_x86_64_defconfig:115)
  - configs/suderra_x86_64_defconfig:21 the only industrial x86 defconfig is PROD, so x86 field devices have no install path at all
  - Config.in variant help text: "Production appliance (locked runtime, no factory provisioning)"; the referenced separate factory profile does not exist
- **Kök neden:** The production variant was defined as 'locked' before a production-grade delivery path for the agent existed. The build-time path was disabled (cargo4 hash gate) and the runtime path (SSH provisioning) is excluded by design, leaving no path.
- **Mimari düzeltme yönü:** Choose one delivery architecture and enforce it. Either (a) embed the agent in the rootfs: fix the cargo4 vendor hash, make the gate selectable, and ship agent updates as signed RAUC bundles; or (b) build a prod-safe provisioning path with no SSH, e.g. a signed manifest pulled over mTLS or delivered by the USB installer, installed into /data. Add a CI gate that each production defconfig produces an image on which the agent becomes active.
- **Doğrulama:** QEMU prod-ab e2e: fresh flash, boot, agent delivered via the chosen path, agent active, health gate passes, mark-good.

<a id="EI-008"></a>

### EI-008 — RAUC health gate fails whenever the agent unit file exists but the agent is not running (always true on prod), and skips the declared verity/LUKS/rollback-floor checks

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-rauc-health-gate / suderra-rauc-mark-good
- **Köken:** doğrulanan iddia T82 (CONFIRMED)
- **Kanıt (dosya:satır):** `package/suderra-rauc-config/suderra-rauc-health-gate:25-29`, `package/suderra-rauc-config/suderra-rauc-mark-good:18-27`, `userspace/suderra-ota/src/main.rs:238-261`, `ci/evidence-contract.yml:641-647`, `tests/qemu/app-startup-test.sh:19`, `package/suderra-rauc-config/suderra-rauc-mark-good.service:5`
- **Kanıt (ayrıntı):**
  - package/suderra-rauc-config/suderra-rauc-health-gate:25-29 if `systemctl list-unit-files suderra-agent.service` succeeds, the agent must be active. The overlay ships that unit on every image (rootfs-overlay/etc/systemd/system/suderra-agent.service) while prod has no agent (T80), so ConditionPathExists leaves it inactive and the gate fails
  - package/suderra-rauc-config/suderra-rauc-mark-good:18-27 on gate failure runs `suderra-ota rollback --reason health-gate` (userspace/suderra-ota/src/main.rs:238-261: rauc mark-bad + /sbin/reboot) or rauc mark-bad + reboot, so every prod boot is marked bad and rebooted
  - Gate checks only rauc presence, /data and /boot mountpoints, slot letter and agent; ci/evidence-contract.yml:641-647 (and :695-701) require dm-verity-active, data-luks-open and rollback-floor-current, none of which the gate checks (mountpoint /data is not LUKS proof)
  - tests/qemu/app-startup-test.sh:19 enforces the agent is-active check
  - Upstream, suderra-rauc-mark-good.service:5 Requires=suderra-data.service and :20 ReadWritePaths=/data (absent in rootfs), so mark-good may never start at all (see incidental), which leaves the bootloader try counters to exhaust
- **Kök neden:** The gate was written for an image with an embedded agent and infers 'agent expected' from unit-file presence instead of from deployment state. Its checks are hand-picked, not derived from the evidence contract they claim to satisfy.
- **Mimari düzeltme yönü:** Generate or validate the gate from the evidence contract's health_checks list, so every declared check has an implementation. Make the agent check conditional on a persistent install record (agent-installed state on /data written by the installer), not on unit-file existence. Add real verity (dmsetup status suderra-root), LUKS mapper and rollback-floor checks.
- **Doğrulama:** QEMU prod-ab: a boot without an installed agent marks good; a boot with an installed but crashing agent rolls back. A contract test parses evidence-contract.yml and asserts each health_check token has a gate implementation.

<a id="EI-009"></a>

### EI-009 — x86_64 kernel has no initramfs support, so the UKI's verity initramfs is ignored and root=/dev/mapper/suderra-root never appears

- **Önem:** Kritik · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86_64 kernel config / UKI
- **Köken:** doğrulanan iddia T94 (CONFIRMED)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:475-481`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/linux-x86_64.config - no CONFIG_BLK_DEV_INITRD (file read in full)
  - linux 6.12 init/Kconfig:1368-1370 - BLK_DEV_INITRD has no default; the only select is BOOT_CONFIG (init/Kconfig:1388-1390), which is not enabled
  - buildroot/linux/linux.mk:460-461 - Buildroot enables BLK_DEV_INITRD only for BR2_TARGET_ROOTFS_CPIO, which no x86 defconfig sets
  - scripts/production-artifacts.sh:475-481 - the dm-verity setup lives only in the UKI .initrd section; :272 root=/dev/mapper/suderra-root ro rootwait
  - Without BLK_DEV_INITRD the EFI stub skips initrd loading and init uses noinitramfs. The kernel then waits indefinitely (rootwait) for a mapper device nobody creates.
- **Kök neden:** Same stale hand-written x86 config as T92. The UKI design (initramfs-based verity) was added in scripts without updating the kernel. No executed boot of the real x86 prod kernel config gates releases.
- **Mimari düzeltme yönü:** Add BLK_DEV_INITRD=y and RD_GZIP=y, or set up verity without an initramfs via CONFIG_DM_INIT with dm-mod.create= in the signed UKI cmdline (and root=/dev/dm-0). Derive the required kernel options from the boot design in one contract file checked against the final .config.
- **Doğrulama:** QEMU OVMF Secure Boot boot of suderra_x86_64 (real hardware defconfig, not only qemu_prod_ab) must reach multi-user with 'dmsetup table suderra-root' showing verity. CI .config assertion BLK_DEV_INITRD=y for UKI-based targets.

<a id="EI-010"></a>

### EI-010 — suderra-data.service cannot start because its ReadWritePaths name directories absent from the rootfs (226/NAMESPACE), and even if it started, the /data and bind mounts it makes stay inside its private mount namespace

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** rootfs-overlay suderra-data.service + suderra-data-unlock (and other units with ReadWritePaths)
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-data.service:14-17`, `package/suderra-rauc-config/suderra-rauc-mark-good.service:5`, `package/suderra-rauc-config/system.conf.arm:5`
- **Kanıt (ayrıntı):**
  - Spot-checked: board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-data.service:14-17 NoNewPrivileges/ProtectHome/PrivateTmp/ReadWritePaths=/data /var/lib/suderra /var/log/suderra /opt/suderra/edge/releases /dev/mapper, with no '-' prefixes
  - Spot-checked: debugfs of output/suderra_qemu_x86_64_defconfig/images/rootfs.ext2 shows /data, /var/log/suderra and /opt/suderra missing (/opt is empty); nothing in board/, package/ or scripts creates them
  - systemd 256.17 src/core/namespace.c:373-376 ('-' prefix is the only ENOENT ignore) and :1556-1566 (ENOENT is fatal) make the exec fail with 226/NAMESPACE before suderra-data-unlock runs
  - namespace.c:2560-2563 mount(/, MS_SLAVE|MS_REC) and :2633-2636 MS_SHARED ('this will not reestablish propagation from our side to the host'): `mount -L SUDERRA-DATA /data` and the binds at suderra-data-unlock:12-20,135-139 would be invisible to every other unit
  - Consequences: /data is never mounted for the host; suderra-rauc-health-gate:11 `mountpoint -q /data` fails; suderra-rauc-mark-good.service:5,20 (Requires=suderra-data.service, ReadWritePaths=/data) cannot start; system.conf.arm:5 statusfile=/data/rauc/status.ini
  - Same missing-path pattern: the overlay suderra-agent.service:37 ReadWritePaths includes /var/log/suderra, which only firstboot creates (dev only), so on prod the agent unit would also fail with 226/NAMESPACE once its ConditionPathExists checks pass; provision-worker /opt/suderra is claim T65
- **Kök neden:** A unit whose job is to create system-wide mounts is hardened with namespacing directives, which both require the paths to pre-exist and isolate every mount it makes; mount points are not created at build time from the mount plan.
- **Mimari düzeltme yönü:** Express storage declaratively: crypttab/systemd-cryptsetup (tpm2-device=auto), a data.mount unit and bind .mount units (var-lib-suderra.mount, opt-suderra-edge-releases.mount), with mount points created in TARGET_DIR at build time; remove namespacing from any unit that must mount. Add an image contract that every ReadWritePaths entry of every unit exists in the rootfs or is '-'-prefixed, and a QEMU check that findmnt /data succeeds in the host namespace.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-011"></a>

### EI-011 — systemd pre-expands the inline firstboot shell: ${pass}/${hash} become empty and %s becomes /bin/sh, so the provision account gets an empty shadow field, credentials.env and the console show "/bin/sh", and the config skeleton is written as repeated "/bin/sh" lines

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/default/dropbear:5`
- **Kanıt (ayrıntı):**
  - Spot-checked: suderra-firstboot.service:31-84 is one ExecStart=/bin/sh -c '...' containing printf "%s\n" (:53), "${pass}"/"${hash}" (:72-75) and 'Password: %s' (:78), with no $$ or %% escaping and no Environment= defining pass/hash
  - systemd 256.17 src/core/load-fragment.c:1034-1040 applies unit_full_printf() to every ExecStart word; src/core/unit-printf.c:243 '%s' -> specifier_user_shell (manager shell /bin/sh)
  - systemd 256.17 src/core/exec-invoke.c:5315-5333 replace_env_argv() and src/basic/env-util.c:690-735 replace ${VAR} on every argv word; unset vars become empty ('Referenced but unset environment variable evaluates to an empty string')
  - systemd 256.17 src/shared/conf-parser.c:356 drops comment lines inside continuations, so the script survives and only %/${} are mangled
  - Result: sed runs as s#^provision:[^:]*:#provision::# (empty shadow field); credentials.env and /dev/console get '/bin/sh' instead of the password; config.yaml becomes repeated '/bin/sh' lines
  - dropbear 2025.88 src/svr-authpasswd.c:100-105 / svr-auth.c:125-130 reject blank passwords without -B (etc/default/dropbear:5), so SSH provisioning is impossible even on revpi4/rpi4 dev images that ship openssl; independent of claims T66/T67/T68
- **Kök neden:** Non-trivial shell logic is embedded in an ExecStart= line, where systemd specifier (%) and environment (${}) expansion run before /bin/sh sees the text; nothing tests the result on a booted image.
- **Mimari düzeltme yönü:** Move firstboot into the packaged suderra-firstboot binary or a /usr/libexec script invoked by ExecStart=; add a lint rejecting '%' and '${' inside inline sh -c ExecStart= words in overlay units (or require $$/%% escaping) and run systemd-analyze verify in CI. QEMU test: provision shadow field is a valid $6$ hash and config.yaml parses.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-012"></a>

### EI-012 — suderra-rauc-mark-good rolls back (mark-bad + reboot) on every normal boot without a pending OTA, because `suderra-ota mark-good` errors "no pending version to mark good" and its failure triggers rollback

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-rauc-config/suderra-rauc-mark-good + userspace/suderra-ota mark_good
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `package/suderra-rauc-config/suderra-rauc-mark-good:29-33`, `userspace/suderra-ota/src/main.rs:264-271`, `package/suderra-rauc-config/suderra-rauc-config.mk:55-56`, `scripts/production-artifacts.sh:540-545`, `board/suderra/x86_64/grub.cfg:78-79`
- **Kanıt (ayrıntı):**
  - Spot-checked: package/suderra-rauc-config/suderra-rauc-mark-good:29-33 runs /usr/bin/suderra-ota mark-good and on failure `suderra-ota rollback --reason mark-good-failed`
  - Spot-checked: userspace/suderra-ota/src/main.rs:264-271 mark_good bails with 'no pending version to mark good' when no --version is passed and state.pending_version is None (every boot without a pending OTA, including the first factory boot); rollback() (:238-262) runs rauc status mark-bad and requests a reboot
  - BR2_PACKAGE_SUDERRA_OTA=y in every prod defconfig; suderra-rauc-config.mk:55-56 links suderra-rauc-mark-good.service into multi-user.target.wants
  - scripts/production-artifacts.sh:540-545 initial B_OK=0, so after A is marked bad grub.cfg:78-79 halts; on ARM slot B is empty and verity fails, so the device boot-loops
  - Currently masked by claim T82 (the health gate fails first) and by suderra-data.service failing (mark-good Requires it); it fires as soon as those are fixed
- **Kök neden:** The mark-good flow conflates "confirm a pending update" with "every boot", and treats the expected state of having no pending update as an update failure.
- **Mimari düzeltme yönü:** Run mark-good/rollback only when RAUC reports the booted slot in a try/pending state; a normal boot of an already-good slot is a no-op. Never mark-bad the only bootable slot. QEMU prod test: boot four times with no OTA and the slot stays good.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-013"></a>

### EI-013 — FIT signature never enforced on Pi: keyed u-boot.dtb is not U-Boot's control FDT, and verity/lockdown bootargs never reach the kernel

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM signed-FIT root of trust
- **Köken:** doğrulanan iddia T88 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/uboot-fragment.config:24-25`, `scripts/production-artifacts.sh:656`, `board/suderra/common/post-image.sh:630-653`, `docs/architecture/ADR-0007-arm-verity-ab-boot-chain.md:142-152`, `scripts/production-artifacts.sh:386-401`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/uboot-fragment.config:24-25 - only CONFIG_OF_CONTROL=y; no OF_SEPARATE
  - U-Boot v2025.04 arch/arm/Kconfig:662-674 - ARCH_BCM283X implies OF_HAS_PRIOR_STAGE; dts/Kconfig:170-172 OF_BOARD default y if OF_HAS_PRIOR_STAGE; board/raspberrypi/rpi/rpi.c:539-547 board_fdt_blob_setup returns the firmware DTB
  - U-Boot Makefile:1255-1256 - without OF_SEPARATE, u-boot.bin is u-boot-nodtb.bin, so the keyed u-boot.dtb is only a loose FAT file nobody loads (genimage-prod.cfg:22)
  - U-Boot boot/image-fit-sig.c:489-495 - no /signature node in the control FDT returns 0, so any FIT boots, including unsigned ones
  - scripts/production-artifacts.sh:656 puts the verity/rauc.slot/lockdown cmdline in a FIT configuration 'bootargs' property. U-Boot has no such FIT property (include/image.h:1078-1105) and takes the cmdline from env 'bootargs' (boot/fdt_support.c:321-326,367-371). The default rpi.env defines none.
  - board/suderra/common/post-image.sh:630-653 - the prod gate checks the keyed loose u-boot.dtb file, which gives false assurance
  - docs/architecture/ADR-0007-arm-verity-ab-boot-chain.md:142-152 already flags the control-FDT doubt as G4
- **Kök neden:** The design assumed mainline U-Boot semantics: OF_SEPARATE control DTB and FIT-config bootargs. Neither holds for rpi_arm64 (firmware-provided DT; bootargs only from env). The 'proof' is a build-time inspection of an artifact that is not on the runtime path.
- **Mimari düzeltme yönü:** Hardware root of trust first: provision Raspberry Pi secure boot (OTP key hash; signed boot.img containing firmware config, U-Boot or kernel, DTB and cmdline per slot, e.g. tryboot A/B). Otherwise inject the required key into every DTB the firmware loads and authenticate those DTBs via the signed boot.img. Put the cmdline into the signed FIT's DTB /chosen/bootargs and make U-Boot unable to override it (no env bootargs: CONFIG_BOOTARGS unset + writeable-list). Replace the file-inspection gate with an executed boot test that must reject an unsigned/tampered FIT.
- **Doğrulama:** Hardware/QEMU G4 test: (1) a re-signed FIT with an attacker key must fail to boot; (2) an unsigned FIT must fail; (3) /proc/cmdline on the booted device must contain suderra.verity.root_hash and lockdown=confidentiality; (4) editing uboot.env bootargs must not change /proc/cmdline.

<a id="EI-014"></a>

### EI-014 — GRUB never marks a slot as being tried, so a slot that fails before userspace boot-loops forever with no fallback

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86 GRUB A/B bootchooser
- **Köken:** doğrulanan iddia T96 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/x86_64/grub.cfg:54-70`, `scripts/production-artifacts.sh:364-367`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/grub.cfg:54-70 - if TRY!=0 it sets TRY=0 and boots; if OK=1 it boots; nowhere sets <slot>_TRY=1 before booting
  - RAUC GRUB backend: install sets ORDER='B A', B_OK=1, B_TRY=0, so a broken B is selected on every boot
  - scripts/production-artifacts.sh:364-367 - initramfs die() does reboot -f, which repeats the same slot. Kernel panics also repeat (panic=10).
  - grub.cfg comment :3-6 claims RAUC semantics that the logic does not implement
- **Kök neden:** The boot-counting half of RAUC's reference grub.cfg (set TRY=1 before boot; skip slots with TRY=1 and OK=1) was inverted or omitted. No negative test boots a deliberately broken slot.
- **Mimari düzeltme yönü:** Implement RAUC's documented scheme: for each slot in ORDER, skip it unless OK=1 and TRY=0. Before chainloading, set <slot>_TRY=1 and save_env. Userspace mark-good resets TRY. Generate grub.cfg from the RAUC contract, not by hand.
- **Doğrulama:** QEMU prod-ab negative test: install a bundle whose UKI panics (or whose verity hash is wrong). Assert the next boot returns to slot A and RAUC reports B bad.

<a id="EI-015"></a>

### EI-015 — Provisioning credential is a console-printed shared password stored in plaintext, and openssl (needed to hash it) is missing on two dev images

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-firstboot.service / etc/default/dropbear / defconfigs
- **Köken:** doğrulanan iddia T68 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:72-75`, `board/suderra/aarch64-revpi4/cmdline.txt:1`, `board/suderra/common/rootfs-overlay/etc/default/dropbear:5`, `configs/suderra_qemu_x86_64_defconfig:101`, `configs/suderra_aarch64_defconfig:83`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:72-75 generates the password, hashes it with `openssl passwd -6` and writes SUDERRA_PROVISION_PASSWORD in plaintext to /var/spool/suderra-provision/credentials.env (0600 root, on persistent rootfs, never deleted unless lockdown succeeds)
  - suderra-firstboot.service:78 printf "...Password: %s" > /dev/console (serial0 + tty1 per board/suderra/aarch64-revpi4/cmdline.txt:1)
  - board/suderra/common/rootfs-overlay/etc/default/dropbear:5 DROPBEAR_ARGS="-w -j -k -I 600 -K 60": no -s, so password auth stays enabled
  - configs/suderra_qemu_x86_64_defconfig:101 and configs/suderra_aarch64_defconfig:83 BR2_PACKAGE_OPENSSL=y without BR2_PACKAGE_LIBOPENSSL_BIN; the built qemu target has no usr/bin/openssl, so :73 fails under set -e and firstboot aborts on every boot (.firstboot-done is never written)
  - Worse, independent of openssl: systemd expands ${pass} and ${hash} inside ExecStart to empty strings (see incidental), so even revpi4/rpi4 dev images get a blank provision password
- **Kök neden:** Device bootstrap trust is a shared secret shown on a physical console instead of a cryptographic identity. The password logic is inline shell inside a unit file, and its tool dependency is not declared in Kconfig.
- **Mimari düzeltme yönü:** Replace password bootstrap with key-based provisioning. The image (or the USB installer/factory step) carries the provisioning CA or panel public key in an authorized_keys file read by dropbear, with -s and a forced command. Lockdown revokes the key by deleting that file. No secret is ever printed or stored. If any generated secret remains, move the logic into a real script or Rust binary whose dependencies are selected in Kconfig, and delete the credential after first use.
- **Doğrulama:** Image contract test: dropbear args contain -s, no credentials.env exists, and firstboot contains no /dev/console write. QEMU test: password auth is refused and key auth with the forced command succeeds.

<a id="EI-016"></a>

### EI-016 — Cloud sends the provisioning token as an extra SSH argument, which the device drops; the manifest fetch has no token and gets 401

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-provision / suderra-edge-install (and cloud installer-script.service.ts)
- **Köken:** doğrulanan iddia T69 (CONFIRMED)
- **Kanıt (dosya:satır):** `aquaculture_platform/apps/sensor-service/src/edge-device/installer-script.service.ts:236`, `aquaculture_platform/apps/sensor-service/src/edge-device/provisioning.controller.ts:146-159`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:42-50`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:75-85`
- **Kanıt (ayrıntı):**
  - aquaculture_platform apps/sensor-service/src/edge-device/installer-script.service.ts:236 builds `ssh provision@IP install-manifest-url <url> X-Provisioning-Token:<token>`
  - aquaculture_platform apps/sensor-service/src/edge-device/provisioning.controller.ts:146-159 GET install/:deviceCode/suderra-os returns 401 when the x-provisioning-token header is missing
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:42-50 writes only "$2" to inbox/manifest-url; $3 (the token) is silently ignored, and extra args are not rejected
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:75-85 curl call with no -H header, so the --fail exit 22 under set -eu aborts the install
  - Side effect: the token sits in the ssh command line, so it is visible in device process argv (/proc/*/cmdline) and in the client's shell history
- **Kök neden:** The forced-command grammar exists twice, once in the cloud TypeScript and once in device shell, with no shared versioned contract. The device parser is positional and permissive, so it fails open by ignoring unknown arguments.
- **Mimari düzeltme yönü:** Define one versioned provisioning command schema shared by both repos, e.g. a JSON request on stdin {manifest_url, token} validated by the device. The device writes the token to a root-only request file, and edge-install passes it with `curl -H @file`, so it never appears in argv. The device rejects any unknown or extra argument.
- **Doğrulama:** Keep a shared fixture of command and request bytes in both repos. The cloud unit test asserts the generator emits it. The device test feeds it to suderra-provision and asserts that a local HTTPS test server receives the X-Provisioning-Token header.
- **Not:** Adversarial re-check rated HIGH (verifier CRITICAL): CONFIRMED mechanism, severity lowered from CRITICAL. The command builder buildSuderraOsInstallerCommand has no callers in apps/, web/ or libs/ (dead code, no test). The device protocol also offers install-manifest-json over stdin, which needs no device-side token, so the URL path is broken but it is not the only path. The decisive chain-breaker is a different one: the cloud's manifest schema is unsigned and incompatible with the device verifier (see incidental). Argv exposure is real: dropbear runs `suderra-provision -c "<cmd>"`, so the token sits in /proc/<pid>/cmdline for up to 900 s and in the operator's shell history. TITLE: The cloud's SSH provisioning command puts the token in a third argument that the device silently ignores, so the manifest fetch gets 401. ROOT CAUSE: The forced-command grammar exists twice, in TypeScript and in device shell, with no shared versioned contract. The device parser is positional and fails open on extra arguments. FIX: Define one versioned provisioning-request contract (a JSON Schema in a shared package) and generate both sides from it. Make the device parser strict (exit 2 when $# != 2). Never put the token on argv: the cloud fetches and signs the manifest and pushes it via stdin, so the device needs no fetch credential. TEST: A cloud CI contract test feeds generated commands to the real suderra-provision parser. A device unit test asserts that extra arguments are rejected.

<a id="EI-017"></a>

### EI-017 — Release layout is split between the read-only, per-slot rootfs (current link) and /data (releases), and the bind mounts hide the package's own outputs

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install release layout / suderra-data-unlock / suderra-edge-agent.mk
- **Köken:** doğrulanan iddia T73 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:9`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:11-20`, `package/suderra-rauc-config/system.conf.arm:16-34`, `package/suderra-edge-agent/suderra-edge-agent.mk:20-33`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:9 CURRENT_LINK=/opt/suderra/edge/current (rootfs); :272 ln -sfn releases/${VERSION} current
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:11-20 bind-mounts /data/suderra/releases over /opt/suderra/edge/releases and /data/suderra/lib over /var/lib/suderra
  - scripts/production-artifacts.sh ~422-423: the prod rootfs is `dmsetup create suderra-root --readonly` and `mount -o ro`, so ln -sfn fails with EROFS on prod; RAUC replaces the whole rootfs slot (package/suderra-rauc-config/system.conf.arm:16-34), so the link is lost on slot switch
  - package/suderra-edge-agent/suderra-edge-agent.mk:20-33 installs config.yaml into TARGET_DIR/var/lib/suderra/config and the binary into TARGET_DIR/opt/suderra/edge/releases/<sha>; both are shadowed by the binds, leaving current dangling
  - Note: the binds currently do not take effect at all, because suderra-data.service fails or runs in a private mount namespace (see incidental)
- **Kök neden:** Mutable deployment state (which agent release is active) lives on the immutable, per-slot rootfs. Build-time packaging writes into directories that become mount points at runtime, and no rule says mount points must be empty in the image.
- **Mimari düzeltme yönü:** Keep the active-release pointer in the persistent store (e.g. /data/suderra/edge/current) and give the unit a stable ExecStart path on /data, or have a systemd generator resolve it into /run. Either the agent ships in the rootfs and is updated via RAUC, or it lives only on /data, never both. Add a post-build assertion that every bind or mount target directory is empty in TARGET_DIR.
- **Doğrulama:** Post-build contract test that mountpoint dirs are empty. QEMU prod-ab test: install the agent, perform a RAUC slot switch, reboot, and assert the agent is still active on the same release.

<a id="EI-018"></a>

### EI-018 — Board detection has no x86 branch (exits 2), and on RevPi Connect 4 it will report rpi4-cm4

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install detect_board
- **Köken:** doğrulanan iddia T74 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:41-55`, `board/suderra/common/rootfs-overlay/etc/suderra/edge-install.env:11-17`, `userspace/suderra-installer/src/contracts.rs:336-359`, `configs/suderra_x86_64_defconfig:73`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:41-55 handles only $SUDERRA_TARGET_BOARD or /proc/device-tree/model matching RevPi/Raspberry Pi; otherwise `exit 2`. x86 has no /proc/device-tree and the worker/env file never sets SUDERRA_TARGET_BOARD (etc/suderra/edge-install.env:11-17)
  - Called unconditionally for manifest installs at :171
  - RevPi: configs/suderra_aarch64_revpi4*_defconfig:29-36 use the raspberrypi/linux kernel with bcm2711-rpi-cm4 DTBs; board/suderra/aarch64-rpi4/config.txt and config-uboot.txt load no revpi overlay (only disable-bt). The DT model is therefore the CM4 string, the case at :49 never matches, and :50 returns rpi4-cm4, so manifests issued for board revpi4 fail check_edge_target (userspace/suderra-installer/src/contracts.rs:336-359)
- **Kök neden:** Board identity is inferred at runtime from a free-form DT string in shell rather than fixed at build time from the defconfig, which already knows the target (post-build.sh writes IMAGE_ROLE).
- **Mimari düzeltme yönü:** Make board identity a build-time fact. post-build writes SUDERRA_BOARD=<id> into /etc/os-release from the defconfig (single source shared with the cloud's board enum), and suderra-installer reads it. Hardware probing (DMI on x86, DT compatible on ARM) may only cross-check, never decide.
- **Doğrulama:** Contract test: every defconfig yields a SUDERRA_BOARD value that is in the manifest schema's board enum. Unit test of the detection function on x86 (no DT) and on a CM4 DT.

<a id="EI-019"></a>

### EI-019 — Agent user has no device groups and the OS ships no udev rules, so DeviceAllow alone cannot grant field I/O

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** users.txt / udev / suderra-agent.service DeviceAllow
- **Köken:** doğrulanan iddia T84 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/users.txt:26`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:62-72`, `aquaculture_platform/sens-api-gateway/src/gpio.rs:397-405`, `aquaculture_platform/sens-api-gateway/src/gpio.rs:461`
- **Kanıt (ayrıntı):**
  - board/suderra/common/users.txt:26 suderra 200 ... groups '-' (none); built image /etc/group shows dialout:x:18: with no members
  - No *.rules file under board/ or package/
  - systemd 256.17 rules.d/50-udev-default.rules.in:42 gives tty[A-Z]*[0-9] (ttyAMA0, ttyUSB0) group dialout 0660; there are no rules for i2c-*, spidev*, gpiomem or tpmrm0, which stay root-only (kernel default 0600)
  - rootfs-overlay/etc/systemd/system/suderra-agent.service:62-72 DeviceAllow lists gpiomem, i2c-1, spidev0.x, ttyAMA0, ttyUSB0 and tpm*. DeviceAllow is a cgroup filter only and does not override DAC, so Modbus-RTU, I2C sensors, SPI and GPIO all fail with EACCES
  - Compat gaps: no ttyS*/ttyACM* (industrial x86 serial), only a single ttyUSB0, no RevPi /dev/piControl0 (PiBridge), and the kernel/DT have no piControl support
- **Kök neden:** Device access was modelled only on the systemd cgroup layer, without the DAC layer (groups and udev ownership). Each board's I/O inventory is not described in one place from which both layers could be generated.
- **Mimari düzeltme yönü:** Create one per-board device manifest that generates (a) udev rules assigning the exact nodes to a dedicated group (e.g. suderra-io), (b) the agent's SupplementaryGroups= or users.txt group membership, and (c) the DeviceAllow= list, so the layers cannot drift. Include ttyS*, ttyACM* and ttyUSB* globs on x86, and piControl0 plus RS485 on RevPi.
- **Doğrulama:** QEMU test: as uid 200 inside the agent unit sandbox, open each manifest-listed node (emulated serial, i2c-stub, spidev) successfully. Contract test: every DeviceAllow entry has a matching udev rule granting the agent's group.

<a id="EI-020"></a>

### EI-020 — x86_64 production kernel has no dm-crypt, so LUKS2 /data cannot be formatted or opened

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86_64 kernel config
- **Köken:** doğrulanan iddia T92 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/x86_64/linux-x86_64.config:68-71`, `board/suderra/common/kernel-fragment.config:23-26`, `configs/suderra_x86_64_defconfig:83`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:67`, `board/suderra/aarch64-rpi4/linux-rpi4.config:110`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/linux-x86_64.config:68-71 - device-mapper lines commented; no DM_CRYPT and no CRYPTO_USER_API_SKCIPHER anywhere in the file
  - board/suderra/common/kernel-fragment.config:23-26 - BLK_DEV_DM, DM_INIT, DM_VERITY, DM_VERITY_FEC only; no DM_CRYPT
  - linux 6.12 drivers/md/Kconfig:252-254 - DM_CRYPT has no default
  - buildroot: cryptsetup has no LINUX_CONFIG_FIXUPS (not in the fixup package list); lvm2.mk:79-82 enables only MD/BLK_DEV_DM
  - configs/suderra_x86_64_defconfig:83 and qemu_x86_64_prod_ab:77 BR2_PACKAGE_CRYPTSETUP=y; rootfs-overlay/usr/sbin/suderra-data-unlock:67,113-126 rely on luksFormat/systemd-cryptsetup
  - Contrast board/suderra/aarch64-rpi4/linux-rpi4.config:110 CONFIG_DM_CRYPT=y
- **Kök neden:** The x86 kernel config is a hand-maintained minimal list from 'Faz 1' that was never updated as LUKS /data became a prod requirement. No test cross-checks userspace features against the effective kernel config.
- **Mimari düzeltme yönü:** Add DM_CRYPT=y, CRYPTO_USER_API_SKCIPHER=y, CRYPTO_XTS/ESSIV/ARGON2-capable deps to a shared prod kernel fragment used by every prod board. Make it detectable: a 'kernel capability contract' (e.g. ci/kernel-requirements.yml mapping each enabled package or runtime script to required symbols), checked against the final .config of each defconfig.
- **Doğrulama:** QEMU prod-ab with swtpm: first boot must produce /dev/mapper/suderra-data, mounted on /data, with cryptsetup luksDump showing a systemd-tpm2 token. CI .config assertion for DM_CRYPT=y on all prod defconfigs.
- **Not:** Adversarial re-check rated HIGH (verifier CRITICAL): Confirmed by reproducing Buildroot's merge in scratch: linux-x86_64.config, then kernel-fragment.config, then olddefconfig, then the package fixups (systemd, skeleton-init-systemd, nftables, lvm2), then olddefconfig again, on linux 6.12.6. The result has '# CONFIG_DM_CRYPT is not set' and '# CONFIG_CRYPTO_USER_API_SKCIPHER is not set', so LUKS2 /data cannot be opened on x86 prod. Rated HIGH, not CRITICAL: it fails closed (no data exposure), it is masked by T94, and the target is release:false.

<a id="EI-021"></a>

### EI-021 — x86_64 kernel lacks conntrack/ct/limit, so the nftables ruleset fails to load and boot continues with no firewall

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86_64 kernel netfilter / firewall unit
- **Köken:** doğrulanan iddia T93 (PARTIAL)
- **Kanıt (dosya:satır):** `board/suderra/x86_64/linux-x86_64.config:78-82`, `board/suderra/common/rootfs-overlay/etc/nftables.conf:18`, `board/suderra/common/rootfs-overlay/etc/nftables.provisioning.conf:16`, `board/suderra/common/rootfs-overlay/etc/systemd/system/nftables.service:6-8`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/linux-x86_64.config:78-82 - only NETFILTER, NETFILTER_NETLINK, NF_TABLES
  - PARTIAL: buildroot/package/nftables/nftables.mk:54-58 forces CONFIG_NF_TABLES_INET=y via LINUX_CONFIG_FIXUPS, so 'inet' tables are supported (that sub-claim is false)
  - linux 6.12 net/netfilter/Kconfig:82-84 - NF_CONNTRACK defaults only when NETFILTER_ADVANCED=n (default y, net/Kconfig:211-214); :512-514 NFT_CT depends on NF_CONNTRACK; :541-542 NFT_LIMIT has no default
  - board/suderra/common/rootfs-overlay/etc/nftables.conf:18,21-22,40 and nftables.provisioning.conf:16,20,22 use 'ct state' and 'limit', so nft -f rejects the whole transaction
  - rootfs-overlay/etc/systemd/system/nftables.service:6-8,23 - only Before=/Wants=network-pre.target and WantedBy=sysinit.target; nothing Requires it, so its failure does not block networking
- **Kök neden:** Kernel netfilter features are not derived from the shipped rulesets. The firewall unit is ordered but not a hard dependency of network bring-up (fail-open by construction).
- **Mimari düzeltme yönü:** Add NF_CONNTRACK, NFT_CT, NFT_LIMIT, NFT_REJECT(_INET), NF_REJECT_IPV4/6 and NFT_LOG to the shared prod fragment. Make network bring-up depend on the firewall: systemd-networkd.service drop-in Requires=/After=nftables.service, plus nftables.service FailureAction=reboot (or a drop-all fallback ruleset compiled into the kernel). CI: run 'nft -c -f' for both rulesets inside the QEMU prod kernel.
- **Doğrulama:** QEMU prod-ab boot: assert 'nft list ruleset' is non-empty and contains policy drop. Negative test: a deliberately broken ruleset must leave the interface down or the device rebooted, never online without a firewall.

<a id="EI-022"></a>

### EI-022 — RPi4/RevPi dev and RPi USB-installer images boot with root=LABEL= and no initramfs; the kernel cannot resolve LABEL=, so boot hangs on rootwait

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** board/suderra/aarch64-rpi4|aarch64-revpi4|aarch64-rpi4-usb-installer cmdline.txt
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/cmdline.txt:1`, `board/suderra/aarch64-revpi4/cmdline.txt:1`, `board/suderra/aarch64-rpi4-usb-installer/cmdline.txt:1`, `board/suderra/aarch64-rpi4/config.txt:19`, `board/suderra/common/post-image.sh:306-309`
- **Kanıt (ayrıntı):**
  - Spot-checked: board/suderra/aarch64-rpi4/cmdline.txt:1 and aarch64-revpi4/cmdline.txt:1 use root=LABEL=suderra-root ... rootwait; aarch64-rpi4-usb-installer/cmdline.txt:1 uses root=LABEL=suderra-installer
  - Spot-checked: board/suderra/aarch64-rpi4/config.txt:19 kernel=Image with the initramfs lines commented out (:108-112); no BR2_TARGET_ROOTFS_CPIO in the rpi4/revpi4/usb_installer defconfigs; post-image.sh does not rewrite the dev cmdline
  - linux block/early-lookup.c:226-248 kernel root= supports only PARTUUID=/PARTLABEL=/device names, not LABEL=
  - Prod is unaffected: post-image.sh:306-309 swaps in config-uboot.txt and the FIT cmdline uses root=/dev/mapper/suderra-root (:575)
  - The rpi4 and revpi4 dev images are release:true artifacts (claim T108)
- **Kök neden:** The cmdline relies on a userspace (initramfs/udev) feature without an initramfs; no executed boot test covers the ARM dev and installer images.
- **Mimari düzeltme yönü:** Use root=PARTUUID=<disk-id>-NN generated at post-image from the MBR disk signature, or ship a minimal initramfs; add a static check rejecting root=LABEL=/UUID= when the image has no initramfs, and boot-test the images in QEMU raspi4b/virt.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-023"></a>

### EI-023 — The qemu x86_64 and generic aarch64 dev images ship the provisioning units without suderra-installer or the pinned edge key, so suderra-edge-install exits 2 for every manifest

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** configs/suderra_qemu_x86_64_defconfig, configs/suderra_aarch64_defconfig
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:10-11`, `package/suderra-keys/suderra-keys.mk:81-82`
- **Kanıt (ayrıntı):**
  - Spot-checked: configs/suderra_qemu_x86_64_defconfig has no BR2_PACKAGE_SUDERRA_OS_INSTALLER and only a commented BR2_PACKAGE_SUDERRA_KEYS (:116); configs/suderra_aarch64_defconfig has neither (the rpi4/revpi4 dev defconfigs do set both)
  - Spot-checked: debugfs of the built qemu rootfs.ext2 shows no /usr/bin/suderra-installer, and /etc/suderra contains only edge-install.env (no edge-artifact.ed25519.pub)
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:10-11 and :161-168 exit 2 when the verifier or key is missing; package/suderra-keys/suderra-keys.mk:81-82 is what installs edge-artifact.ed25519.pub
  - The qemu x86_64 dev image is a release:true artifact (claim T108)
- **Kök neden:** Runtime dependencies of the shared overlay scripts (verifier binary, trust root) are not declared in Kconfig; the overlay is shared by all images while the packages are opted in per defconfig.
- **Mimari düzeltme yönü:** Have a suderra-provisioning Kconfig option own the overlay scripts and select SUDERRA_OS_INSTALLER and SUDERRA_KEYS (or ship the scripts from that package); add an image contract that every binary and key referenced by an installed script exists in TARGET_DIR.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-024"></a>

### EI-024 — ARM prod boots the raw kernel DTB embedded in the signed FIT, so config.txt dtparam/dtoverlay (I2C, SPI, watchdog, disable-bt UART routing, TPM, RevPi) are silently dropped in production

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** scripts/production-artifacts.sh FIT build / ARM prod device tree
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:628-660`, `board/suderra/aarch64-rpi4/config-uboot.txt:72-96`
- **Kanıt (ayrıntı):**
  - Spot-checked: scripts/production-artifacts.sh:628-660 incbins each raw *.dtb from binaries_dir into fdt-N and every conf references it; grep finds no fdtoverlay/fdtput step in scripts/ or board/suderra/common
  - Spot-checked: board/suderra/aarch64-rpi4/config-uboot.txt:72-96 dtparam=watchdog/i2c_arm/i2c1/spi and dtoverlay=disable-bt affect only the firmware's own DTB
  - U-Boot v2025.04 board/raspberrypi/rpi/rpi.c:567-602 update_fdt_from_fw copies only model/memreserve/cma/dma-ranges/kaslr-seed/PHY/BT address
  - Extends the TPM-specific note in claim T100 to all field-I/O buses
- **Kök neden:** Pi firmware overlay semantics were assumed to carry over to a U-Boot-selected DTB; U-Boot update_fdt_from_fw copies only a few properties from the firmware DT.
- **Mimari düzeltme yönü:** Apply the required overlays at build time (fdtoverlay) to produce per-board final DTBs from a board capability SSoT, sign those into the FIT, and add a build check that the final DTBs enable the expected nodes (i2c1, spi0, tpm, uart0 pinmux, RevPi nodes).
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-025"></a>

### EI-025 — Lockdown deletes the provisioning spool and runs `systemctl stop suderra-provision-worker.service` from inside that unit, killing edge-install and itself before current.env (the downgrade guard) and the install result are written

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** rootfs-overlay usr/sbin/suderra-lockdown invoked via suderra-provision-worker -> suderra-edge-install
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:88-94`
- **Kanıt (ayrıntı):**
  - Spot-checked: board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:88-94 rm -rf /var/spool/suderra-provision; :101-102 systemctl stop dropbear.service suderra-provision-worker.path suderra-provision-worker.service; :109 pkill -KILL -u provision
  - Lockdown runs as a descendant of the worker (worker:51 -> edge-install:304 -> lockdown); suderra-provision-worker.service has no KillMode (default control-group), so the stop SIGTERMs edge-install and lockdown
  - suderra-edge-install:303-304 runs lockdown before :318-325 writes STATE_DIR/current.env, so the downgrade guard at :213-223 never has state
  - Spot-checked: suderra-provision-worker:51-52 write_result ok runs only after edge-install returns, and the SSH client is cut by `systemctl stop dropbear.service`
  - Latent today because check_ready fails first (claim T70) and sed -i /etc/shadow fails (claim T71)
- **Kök neden:** Teardown runs synchronously inside the transaction it tears down (descendant of the worker cgroup, default KillMode=control-group) with no commit-then-teardown sequence.
- **Mimari düzeltme yönü:** Commit the install record and deliver the result first, then trigger lockdown as its own unit (`systemctl start --no-block suderra-lockdown.service`) ordered after the worker exits; lockdown must never stop its own ancestor. QEMU test: current.env exists and the client receives status=ok after lockdown.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-026"></a>

### EI-026 — Prod images mount a read-only dm-verity root but keep Buildroot REMOUNT_ROOTFS_RW=y, so fstab says rw, no /var tmpfs/factory/overlay exists, and all /var state (installer state, spool, chrony drift, journal) is read-only

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** prod defconfigs / buildroot skeleton-init-systemd
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:422-423`
- **Kanıt (ayrıntı):**
  - Spot-checked: grep finds no REMOUNT_ROOTFS_RW/VAR_FACTORY/OVERLAYFS setting in suderra_x86_64_defconfig, suderra_aarch64_revpi4_prod_ab_defconfig, suderra_aarch64_rpi4_prod_ab_defconfig or suderra_qemu_x86_64_prod_ab_defconfig
  - Spot-checked: buildroot/system/Config.in:503-505 BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW default y; buildroot/package/skeleton-init-systemd/skeleton-init-systemd.mk:18-28 then writes '/dev/root / auto rw' and skips the /var factory/tmpfs
  - Spot-checked: scripts/production-artifacts.sh:422-423 dmsetup create suderra-root --readonly; mount -o ro
  - Affects /var/lib/suderra-installer, /var/spool, chrony and journal state, and /var/lib/suderra whenever the /data bind is missing
- **Kök neden:** The read-only verity root was introduced in the initramfs without aligning the Buildroot rootfs mode that controls /var handling.
- **Mimari düzeltme yönü:** Set "# BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW is not set" with BR2_INIT_SYSTEMD_VAR_FACTORY (or OVERLAYFS) in every prod defconfig, route persistent state explicitly to /data mount units, and add a post-build guard that fails a prod build whose fstab says rw. QEMU prod-ab: findmnt /var is tmpfs and journald runs.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-027"></a>

### EI-027 — The QEMU runtime-scenario driver calls suderra-ota with an invalid CLI and scores any failure as the expected rejection, so OTA, bad-signature and anti-rollback evidence is vacuous

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** rootfs-overlay usr/sbin/suderra-runtime-scenario (QEMU evidence driver)
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:56-67`
- **Kanıt (ayrıntı):**
  - Spot-checked: suderra-runtime-scenario:85-86, :102-103 and :118-119 call `suderra-ota install <bundle>` with one positional, while InstallArgs requires manifest AND bundle (userspace/suderra-ota/src/main.rs:56-67), so the call always errors and falls back to raw `rauc install`
  - Spot-checked: suderra-runtime-scenario:137 uses `suderra-ota install --manifest ...`, a flag InstallArgs does not define; the clap error is reported as 'userspace-rejected', so the downgrade-rejection scenario always passes
  - Related to claim T103 (raw rauc install bypasses the floor)
- **Kök neden:** Evidence scripts are not checked against the CLI they drive, fall back to raw `rauc install`, and treat any non-zero exit (including clap usage errors) as "userspace-rejected".
- **Mimari düzeltme yönü:** Drive suderra-ota with its real arguments (manifest + bundle), remove the raw-rauc fallbacks, and require the specific machine-readable rejection reason from suderra-ota JSON events for negative scenarios; add a contract test running the scenario commands against the real binary.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-028"></a>

### EI-028 — x86_64 kernels are pinned to 6.12.6, about 45 stable releases behind the 6.12.51 that Buildroot hashes and the toolchain headers track

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** configs/suderra_x86_64_defconfig, suderra_qemu_x86_64*_defconfig kernel version
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `configs/suderra_x86_64_defconfig:37`
- **Kanıt (ayrıntı):**
  - Spot-checked: BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.12.6" in configs/suderra_x86_64_defconfig:37, suderra_qemu_x86_64_prod_ab_defconfig:31 and suderra_qemu_x86_64_defconfig:36
  - Spot-checked: buildroot/linux/linux.hash lists linux-6.12.51; dl/linux contains both linux-6.12.6 and linux-6.12.51 tarballs; BR2_KERNEL_HEADERS_6_12 tracks 6.12.51
  - Hash enforcement of this tarball is claim T98
- **Kök neden:** A custom kernel version was pinned once and is not tracked against LTS stable updates or CVE triage.
- **Mimari düzeltme yönü:** Track the Buildroot LTS kernel or a hash-pinned current 6.12.y, add a CI check that the kernel is within N stable releases of the latest LTS, and cover it in VEX/CVE triage.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-029"></a>

### EI-029 — ARM prod has no usable TPM device, so /data provisioning fails closed on every RPi4/CM4/RevPi prod device

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM /data provisioning
- **Köken:** doğrulanan iddia T100 (CONFIRMED)
- **Kanıt (dosya:satır):** `configs/suderra_aarch64_rpi4_prod_ab_defconfig:196-197`, `board/suderra/aarch64-rpi4/linux-rpi4-hardening.config:62-65`, `scripts/production-artifacts.sh:628`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/config.txt and config-uboot.txt - no dtoverlay=tpm-slb9670 or RevPi overlay (only dtparam=spi=on, :78/:83)
  - configs/suderra_aarch64_rpi4_prod_ab_defconfig:196-197 - comment says 'rpi4 keyfile', but suderra-data-unlock:53-57 refuses to run without /dev/tpm*, and RPi4/CM4 has no TPM
  - linux-rpi4-hardening.config:62-65 builds TCG_TIS_SPI, but without a DT node it never probes
  - Prod boots the FIT-embedded DTB (production-artifacts.sh:628,645-655), so firmware overlays would be dropped anyway (U-Boot rpi.c:567-602 copies only a few properties)
- **Kök neden:** The TPM requirement was written into the unlock script, but the board-level enablement (DT node in the boot DTB) and a non-TPM board policy were never implemented. Defconfig comments describe a keyfile path that the code forbids.
- **Mimari düzeltme yönü:** Per-board capability SSoT: RevPi includes the TPM node in the signed FIT DTB (compile the overlay into the DTB at build time with fdtoverlay). RPi4/CM4 prod is either declared unsupported for prod or given an explicit, documented alternative (e.g. an external TPM HAT DT node). post-image gate: prod ARM DTBs must contain a tpm compatible node.
- **Doğrulama:** Build check: fdtget the FIT DTBs for an 'infineon,slb9670' or 'tcg,tpm_tis-spi' node. Hardware: first boot on RevPi Connect 4 shows /dev/tpmrm0 and a provisioned LUKS2 /data. On RPi4 prod the build must fail or mark the board unsupported.
- **Not:** Adversarial re-check rated HIGH (verifier CRITICAL): Confirmed. Neither config.txt has a TPM overlay. The SLB9670 node exists only in the KUNBUS RevPi overlay, which the repo does not ship (T112). The prod FIT DTB never gets firmware overlays. suderra-data-unlock:53-57 refuses to run without /dev/tpm*, and the defconfig comment promising an 'rpi4 keyfile' contradicts that code. Downgraded from CRITICAL because it fails closed (no data exposure), it is masked by the earlier ARM boot failures (T87/T88), and the ARM prod rows are release:false.

<a id="EI-030"></a>

### EI-030 — suderra-ota never runs in production mode, and its target defaults to x86_64, so every ARM OTA manifest is rejected

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-ota
- **Köken:** doğrulanan iddia T102 (CONFIRMED)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:643-645`, `scripts/create-os-update-manifest.py:59`, `board/suderra/common/post-image.sh:352-358`
- **Kanıt (ayrıntı):**
  - userspace/suderra-ota/src/main.rs:643-645 - is_production() only when SUDERRA_OTA_PRODUCTION=1; :653-656 dev_override honours env otherwise
  - main.rs:748-750 - device_target() defaults to 'x86_64'; manifests carry targets rpi4-prod-ab/revpi4-prod-ab/qemu-x86_64-prod-ab (scripts/create-os-update-manifest.py:59, post-image.sh:352-358), rejected at main.rs:400-407
  - A repo-wide grep finds SUDERRA_OTA_PRODUCTION/TARGET/ROLLBACK_FLOOR_SOURCE only in tests (main.rs:983-1036); package/suderra-ota/suderra-ota-mark-good.service and suderra-rauc-mark-good:29-31 set no environment
  - If PRODUCTION were set, main.rs:701-731 would fail every command (no FLOOR_SOURCE/PATH provisioned)
- **Kök neden:** Security mode and device identity are runtime env flags with insecure defaults, instead of facts compiled into the image or read from the read-only rootfs.
- **Mimari düzeltme yönü:** Make it impossible: derive production mode and target from build-time constants (cargo feature/env!() set by the Buildroot package from BR2 variant and board) or from a signed read-only /usr/lib/suderra/ota-identity.json in the verity rootfs. Remove the x86_64 default (unknown target means a hard error). Provide a real monotonic floor (TPM NV index) before enabling the prod build.
- **Doğrulama:** Unit tests: no target configured gives an error. Image contract test: the installed identity file matches the defconfig target. QEMU/ARM: suderra-ota install with a valid rpi4-prod-ab manifest succeeds, and SUDERRA_OTA_NOW/SUDERRA_OTA_RAUC env overrides are ignored on prod images.
- **Not:** Adversarial re-check rated HIGH (verifier CRITICAL): Confirmed: is_production() is env-only, and device_target() defaults to 'x86_64'. That rejects the rpi4-prod-ab, revpi4-prod-ab and qemu-x86_64-prod-ab manifests. Downgraded from CRITICAL for three reasons. Nothing in production invokes 'suderra-ota install'. The env-override weakness can only be used by whoever controls the process env, which is root, and root can bypass with plain rauc anyway (T103). The target mismatch is a loud functional failure, not a silent one. The tests also hide it: suderra-runtime-scenario calls 'suderra-ota install <bundle>' with one positional argument where InstallArgs needs two, and uses a non-existent --manifest flag. So every suderra-ota call there fails at CLI parsing and is covered by '|| rauc install'.

<a id="EI-031"></a>

### EI-031 — Anti-rollback exists only in the suderra-ota wrapper; rauc install (CLI/D-Bus) bypasses the floor

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** anti-rollback
- **Köken:** doğrulanan iddia T103 (CONFIRMED)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:179-187`, `package/suderra-rauc-config/system.conf.arm:13-14`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-runtime-scenario:85-86`, `board/suderra/common/post-build.sh:207-219`
- **Kanıt (ayrıntı):**
  - userspace/suderra-ota/src/main.rs:179-187 - the floor is checked in userspace, then plain 'rauc install' is called
  - package/suderra-rauc-config/system.conf.arm:13-14 and system.conf - no pre-install/install-check handler enforcing the floor; RAUC has no native version floor
  - configs/*prod_ab_defconfig BR2_PACKAGE_RAUC_DBUS=y - the D-Bus Install method is available to root
  - rootfs-overlay/usr/sbin/suderra-runtime-scenario:85-86,102-103,118-119 - falls back to raw 'rauc install' (qemu prod-ab image only, post-build.sh:207-219)
  - docs/security/security-gaps-and-risks.md HW-5 acknowledges it
- **Kök neden:** The version policy sits in a convenience CLI instead of in the component that writes slots and the bootloader.
- **Mimari düzeltme yönü:** Enforce in RAUC itself: an install-check/pre-install handler (system.conf [handlers]) that compares the bundle version with a TPM-NV or bootloader monotonic counter and fails closed. Lock D-Bus to that path. Optionally bind the floor into boot (refuse to boot slots below the floor).
- **Doğrulama:** QEMU prod-ab: 'rauc install old-signed.raucb' and a D-Bus InstallBundle call must both fail with the floor error. Deleting /data/suderra/ota must not lower the floor.

<a id="EI-032"></a>

### EI-032 — RevPi images are generic CM4 images: no KUNBUS kernel, piControl or RevPi device tree, so PiBridge I/O, RS485 and LEDs are unusable

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** RevPi Connect 4 board support
- **Köken:** doğrulanan iddia T112 (CONFIRMED)
- **Kanıt (dosya:satır):** `configs/suderra_aarch64_revpi4_defconfig:28-36`, `docs/operations/install.md:291-295`, `aquaculture_platform/sens-api-gateway/src/hardware_scanner.rs:328`, `package/suderra-os-installer/suderra-os-install:61-92`, `aquaculture_platform/sens-api-gateway/src/hardware_scanner.rs:434-470`, `scripts/production-artifacts.sh:626-660`
- **Kanıt (ayrıntı):**
  - configs/suderra_aarch64_revpi4_defconfig:28-36 and revpi4_prod_ab:28-36 - upstream raspberrypi/linux tarball, bcm2711_defconfig, DTS only bcm2711-rpi-cm4 and bcm2711-rpi-cm4-io
  - revpi4 defconfigs :55 - uses aarch64-rpi4/config.txt (no RevPi overlay); aarch64-revpi4/genimage*.cfg list only cm4 DTBs
  - repo-wide grep: no piControl, KUNBUS or RevPi overlay anywhere (only a test fixture string)
  - docs/operations/install.md:291-295 - 'RevPi-specific GPIO/IO modules not yet active'
  - agent expects /dev/piControl0 (sens-api-gateway/src/hardware_scanner.rs:328,445), but rootfs-overlay suderra-agent.service:62-72 DeviceAllow has no /dev/piControl0
  - package/suderra-os-installer/suderra-os-install:61-92 - RevPi detection needs a KUNBUS model/compatible that the shipped CM4 DTB never provides; it falls back to 'ambiguous CM4'
- **Kök neden:** RevPi was declared a separate target (defconfig header :4-6) but implemented by aliasing the CM4 build. There is no board-capability contract between the OS image, the agent's hardware expectations and the installer.
- **Mimari düzeltme yönü:** Build the RevPi target from the KUNBUS RevPi kernel (RevolutionPi/linux plus piControl) with the revpi-connect4 overlay merged into the signed FIT DTB (RS485, LEDs, TPM, RTC, watchdog). Ship piTest/piControl tooling and the agent DeviceAllow entries. Drive all of it from one board capability SSoT consumed by the OS, installer and agent.
- **Doğrulama:** Hardware lab G4 on RevPi Connect 4 with a DIO/AIO module: /dev/piControl0 present, piTest -d lists modules, agent hardware_scanner reports them, RS485 loopback works, /proc/device-tree/model reports Connect 4, and the installer auto-detects revpi4.
- **Not:** Adversarial re-check rated HIGH (verifier CRITICAL): Confirmed. There is no piControl, no KUNBUS kernel and no RevPi overlay. The only grep hit is installer detection text, and the RevPi defconfigs build only cm4/cm4-io DTBs from the raspberrypi/linux tarball. Downgraded from CRITICAL: there is no security impact, the gap shows up the first time the board is used, and the team documents it, in the build-matrix blocker 'signed-fit-dm-verity-rauc-revpi-io-and-hardware-evidence-missing' and in install.md:291-295. The defconfig header ('not a generic CM4 alias') does contradict the implementation.

<a id="EI-033"></a>

### EI-033 — Hardware watchdog is enabled in firmware and kernel, but nothing opens or feeds it, so there is no hang recovery

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** hardware watchdog (config.txt, kernel, userspace/suderra-watchdog)
- **Köken:** doğrulanan iddia T83 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/config.txt:67`, `board/suderra/aarch64-rpi4/config-uboot.txt:72`, `board/suderra/aarch64-rpi4/config.txt:60-65`, `board/suderra/aarch64-rpi4/linux-rpi4.config:148-150`, `board/suderra/x86_64/linux-x86_64.config:107-110`, `userspace/Cargo.toml:11`, `package/suderra-edge-agent/suderra-agent.service:70-73`, `docs/dev/rust-workspace.md:220`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/config.txt:67 and config-uboot.txt:72 dtparam=watchdog=on (comment at config.txt:60-65 promises reset after 15s); board/suderra/aarch64-rpi4/linux-rpi4.config:148-150 CONFIG_BCM2835_WDT=y; board/suderra/x86_64/linux-x86_64.config:107-110 iTCO_wdt + softdog
  - userspace/Cargo.toml:11 suderra-watchdog is a workspace member, but there is no package/suderra-watchdog (package/ lists only edge-agent, firstboot, keys, os-installer, ota, rauc-config)
  - No RuntimeWatchdogSec drop-in anywhere in rootfs-overlay (etc/systemd has only system/ and network/)
  - package/suderra-edge-agent/suderra-agent.service:70-73 states suderra-watchdog is the sole owner of /dev/watchdog; the agent does not use /dev/watchdog (no reference in sens-api-gateway/src)
  - Linux watchdog drivers arm only when /dev/watchdog is opened, so the device silently runs with no hardware watchdog
- **Kök neden:** Watchdog ownership was assigned to a daemon that was never integrated into the build. Configuration comments and kernel options give an appearance of protection that no runtime component delivers.
- **Mimari düzeltme yönü:** Make it automatic: set RuntimeWatchdogSec (and RebootWatchdogSec) in a system.conf.d drop-in so PID 1 feeds the hardware watchdog, or package and enable suderra-watchdog as the single owner. Add an image contract: if a watchdog driver or dtparam is enabled, a feeder must be configured.
- **Doğrulama:** QEMU with the i6300esb watchdog: hang the system (stop PID1 feeding, or trigger a kernel lockup) and assert a reset within the timeout. Image contract test for the system.conf.d drop-in or package presence.

<a id="EI-034"></a>

### EI-034 — U-Boot environment is a plain file on a permanently rw-mounted FAT with no variable allow-list

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** U-Boot env / ARM boot FAT
- **Köken:** doğrulanan iddia T85 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/uboot-fragment.config:27-44`, `package/suderra-rauc-config/boot.mount.arm:10-16`, `package/suderra-rauc-config/fw_env.config:11`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/uboot-fragment.config:27-44 - CONFIG_ENV_IS_IN_FAT=y, ENV_FAT_FILE="uboot.env", ENV_SIZE=0x4000. The comment at :28-29 says the env is deliberately not locked
  - No CONFIG_ENV_WRITEABLE_LIST, ENV_APPEND or ENV_IS_NOWHERE anywhere in the repo (repo-wide grep finds only the comment at :29)
  - package/suderra-rauc-config/boot.mount.arm:10-16 - /dev/disk/by-partlabel/boot is mounted rw at every boot (WantedBy=local-fs.target)
  - package/suderra-rauc-config/fw_env.config:11 - /boot/uboot.env 0x0000 0x4000
  - U-Boot v2025.04 configs/rpi_arm64_defconfig has no env restriction, so a stored env replaces the whole default env, including bootcmd
- **Kök neden:** RAUC's U-Boot backend needs fw_setenv write access. The team met that by keeping the whole env writable and the FAT mounted rw permanently, instead of limiting the env to the A/B counters. Pi4/CM4 OTP secure boot is not provisioned, so nothing below U-Boot authenticates the FAT either.
- **Mimari düzeltme yönü:** Make it impossible: CONFIG_ENV_WRITEABLE_LIST=y plus CONFIG_ENV_APPEND=y with CONFIG_ENV_FLAGS_LIST_STATIC limited to BOOT_ORDER/BOOT_A_LEFT/BOOT_B_LEFT (integer-typed). bootcmd/bootargs then come only from the compiled-in default env. Mount /boot ro, and remount rw only inside RAUC hooks through a dedicated mount unit. Provision CM4/RevPi OTP secure boot (signed boot.img) so the FAT contents are authenticated.
- **Doğrulama:** On hardware or QEMU (qemu_arm64 with the same fragment), write bootcmd=... and bootargs=... into uboot.env with fw_setenv and reboot. Assert U-Boot ignores them (printenv shows the defaults) while BOOT_x_LEFT changes still apply. Add a build-time check that greps the final u-boot .config for ENV_WRITEABLE_LIST=y.
- **Not:** The finding is moot today in a worse way: see T88 and incidental U-Boot findings (signature not enforced, boot.scr rejected, FIT bootargs ignored).

<a id="EI-035"></a>

### EI-035 — FIT signature enforcement covers only bootm; bootefi/booti/sysboot/PXE/DHCP/USB boot and an interruptible console remain

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** U-Boot command/bootmeth surface
- **Köken:** doğrulanan iddia T86 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/uboot-fragment.config:30`, `board/suderra/aarch64-rpi4/config-uboot.txt:52-53`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/uboot-fragment.config:30 - CONFIG_CMD_BOOTEFI=y set explicitly
  - U-Boot v2025.04 configs/rpi_arm64_defconfig:13 BOOTSTD_DEFAULTS=y, :27 CMD_USB=y, :16-17 PREBOOT 'pci enum; usb start;'
  - U-Boot boot/Kconfig:646-651 - BOOTMETH_DISTRO selects BOOTMETH_EXTLINUX, BOOTMETH_EXTLINUX_PXE and BOOTMETH_EFILOADER
  - U-Boot board/raspberrypi/rpi/rpi.env:77 boot_targets=mmc usb pxe dhcp; stdin=serial,usbkbd (a USB keyboard can also interrupt)
  - U-Boot boot/Kconfig:1495-1497 BOOTDELAY default 2; the fragment never sets -2 or AUTOBOOT_KEYED
  - board/suderra/aarch64-rpi4/config-uboot.txt:52-53 enable_uart=1 / uart_2ndstage=1 (serial console active)
- **Kök neden:** The fragment adds FIT_SIGNATURE on top of a general-purpose distro-boot defconfig and never removes the other boot paths. It assumes signature checking is a property of the board, when in U-Boot it is a property of the bootm FIT path only.
- **Mimari düzeltme yönü:** Prod-only U-Boot fragment: BOOTDELAY=-2, # CONFIG_CMDLINE is not set (or AUTOBOOT_KEYED with a hashed password), # CMD_BOOTEFI/CMD_BOOTI/CMD_BOOTZ/CMD_SYSBOOT/CMD_PXE/CMD_DHCP/CMD_NET/CMD_USB is not set, BOOTSTD disabled. A compiled-in bootcmd should only load and bootm the signed FIT (better: the boot script inside the signed FIT). Keep this in a single U-Boot prod fragment that CI checks against the final .config.
- **Doğrulama:** Final U-Boot .config assertion test (fail if any of these symbols is y). On a QEMU arm64 boot test, send keystrokes during boot and assert no prompt appears. Serve a PXE extlinux.conf on the test network and assert it is never fetched.
- **Not:** Because U-Boot rejects boot.scr (see incidental), this path is not theoretical: bootflow moves on to usb/pxe/dhcp.

<a id="EI-036"></a>

### EI-036 — Production boot.scr is an unsigned legacy script image on a writable FAT, and U-Boot cannot even run it

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM boot script
- **Köken:** doğrulanan iddia T87 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/post-image.sh:303-305`, `board/suderra/aarch64-rpi4/boot.scr.cmd:14-52`, `board/suderra/aarch64-rpi4/genimage-prod.cfg:20-23`
- **Kanıt (ayrıntı):**
  - board/suderra/common/post-image.sh:303-305 - mkimage -A arm64 -T script -C none -d boot.scr.cmd boot.scr (legacy uImage script, no signature)
  - board/suderra/aarch64-rpi4/boot.scr.cmd:14-52 - slot selection/saveenv logic with no integrity protection
  - board/suderra/aarch64-rpi4/genimage-prod.cfg:20-23 - boot.scr placed on the rw FAT
  - U-Boot v2025.04 boot/Kconfig:950-958 - LEGACY_IMAGE_FORMAT defaults n when FIT_SIGNATURE=y; boot/image-board.c:977-981,1108-1111 - legacy script gives 'Wrong image format for "source" command'
- **Kök neden:** The slot chooser was written as a classic distro boot.scr, outside the signed artifact. The interaction between FIT_SIGNATURE and LEGACY_IMAGE_FORMAT was never tested, because no executed ARM boot test exists (only build-time contract greps).
- **Mimari düzeltme yönü:** Move the A/B chooser into the compiled-in, non-overridable default bootcmd (env counters only), or package the script as a signed FIT script image (type=script with signature, sourced via 'source ${addr}:script-1') verified by the required key. Do not re-enable LEGACY_IMAGE_FORMAT.
- **Doğrulama:** Boot test in QEMU arm64 or on a Pi: a tampered boot.scr or uboot.env must not change the selected slot or kernel. An unsigned script must be rejected. The happy path must reach the initramfs with rauc.slot set.
- **Not:** See incidental 'boot.scr rejected' for the deployment-breaking side of this.

<a id="EI-037"></a>

### EI-037 — /data key is sealed to PCR7 only, with no PIN or recovery path; on ARM PCR7 is never measured, so any OS booted on the device can unseal it

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** /data at-rest encryption
- **Köken:** doğrulanan iddia T99 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:73-74`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:73-74 - systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7
  - suderra-data-unlock:83 - --wipe-slot=password, so the TPM is the only unlock path; there is no recovery key or escrow
  - ARM has no UEFI and U-Boot has no MEASURED_BOOT/TPM (uboot-fragment.config; rpi_arm64_defconfig), so PCR7 stays at its reset value and the policy binds to nothing
  - x86: firmware/dbx/db updates change PCR7, so /data is permanently lost (no recovery). Unlock failure exits 1 (:114-126) with no re-provision path.
- **Kök neden:** The x86 measured-boot model (PCR7 = Secure Boot policy) was copied to ARM, which has no measurements. Recovery and key-lifecycle requirements were not part of the design.
- **Mimari düzeltme yönü:** ARM: bind to a policy that actually reflects the boot chain (requires a measured or secure boot chain: RPi secure boot plus U-Boot MEASURED_BOOT extending PCRs with FIT hashes), or use systemd-pcrlock or signed PCR policies. x86: PCR7 + PCR11 signed policy (systemd-measure) so updates do not brick. Always enroll a recovery key escrowed to the fleet backend (encrypted to an HSM key) and document re-provisioning.
- **Doğrulama:** ARM: boot a different SD image on the same RevPi, run systemd-cryptsetup attach; it must fail. x86: simulate a dbx update in OVMF; unlock via the signed policy or recovery must succeed and the device must not brick.

<a id="EI-038"></a>

### EI-038 — Signed edge manifest is not bound to the device, so it can be replayed (including its config and identity) to any device of the same board/arch

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-installer edge-manifest verification
- **Köken:** doğrulanan iddia T76 (CONFIRMED)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/contracts.rs:301-303`, `userspace/suderra-installer/src/contracts.rs:47-49`, `userspace/suderra-installer/src/contracts.rs:476-484`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/contracts.rs:301-303 ensure_nonempty only for device_id, device_code and tenant_id; no comparison with any local identity
  - contracts.rs:47-49 the plan path checks only board/arch (check_edge_target :336-359); no nonce or single-use token in EdgeProvisioningManifest (:99-117)
  - contracts.rs:476-484 + suderra-edge-install:275-287 install the digest-bound config payload (device identity, broker settings) on whichever device runs it, so devices can be cloned within the expires_at window
- **Kök neden:** The OS has no device-bound identity anchor (TPM key, serial or device-generated nonce) for the manifest to commit to, so the signature proves vendor authorship but not who the manifest is for.
- **Mimari düzeltme yönü:** Add a device-binding claim to the signed manifest, such as a hash of the TPM EK/AK public key or the CM4/DMI serial, or a provisioning nonce the device generated and the cloud fetched. The verifier compares it with local identity and records the nonce as consumed.
- **Doğrulama:** Rust tests: a manifest for device A is rejected on device B (mismatched identity) and a replayed nonce is rejected. QEMU e2e replay test.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): FACTS CONFIRMED, severity lowered to MEDIUM. The manifest commits to no local identity; only board and arch are checked. But replay requires the provision credential of the target device. The activation token embedded in the config is single-use on the cloud side (tokenUsedAt is checked, then the token is set to NULL on activation), so a clone cannot activate after the legitimate device. The remaining risk is a pre-activation race by someone who already holds the manifest, and that party could call /activate directly anyway, because the manifest is a bearer secret. TITLE: The signed edge manifest is not bound to a specific device. ROOT CAUSE: The OS has no device-bound identity anchor (a TPM or device-generated key, or a nonce) for the manifest to commit to. FIX: The device generates an identity key, TPM-backed where available, and sends its public key or a nonce in the provisioning request. The manifest includes that key or nonce, the verifier compares it with the local key, and activation requires proof of possession. TEST: A verifier unit test where a manifest issued for key A is rejected on device B, and a cloud test where activation without proof of possession is rejected.

<a id="EI-039"></a>

### EI-039 — Agent anti-rollback guard sits on rootfs, is bypassable by an unsigned env var, and uses version ordering that differs from the verifier's

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install monotonic guard
- **Köken:** doğrulanan iddia T77 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:5`, `userspace/suderra-installer/src/contracts.rs:615-681`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:5 STATE_DIR=/var/lib/suderra-installer/edge on rootfs, not /data: read-only on verity prod (scripts/production-artifacts.sh ~423), per-slot under RAUC, and not writable in the worker sandbox (T65)
  - edge-install:213-223 the downgrade is refused unless SUDERRA_EDGE_ALLOW_SIGNED_ROLLBACK=1; despite the message, nothing is signed. It is a plain env/env-file variable (edge-install.env is sourced at :131)
  - edge-install:88-102 version_key drops pre-release, while contracts.rs:615-681 applies full SemVer pre-release ordering, so 1.0.0 -> 1.0.0-rc.1 is allowed by the shell although it is a downgrade
  - current.env is written only after lockdown succeeds (edge-install:318-325), and lockdown always fails (T70/T71), so the guard is never armed
  - edge-install:23 MIN_ROLLBACK_FLOOR is a static default (v0.1.0-alpha) that is never ratcheted, and contracts.rs never compares manifest.version with rollback_floor, so any unexpired older signed manifest installs on a fresh or reset device
- **Kök neden:** Anti-rollback policy is split between shell and Rust, with two version semantics. Its state lives in volatile or immutable storage, and the exception path is an environment variable rather than a signed authorization.
- **Mimari düzeltme yönü:** Move the monotonic guard into suderra-installer, with one SemVer implementation. Persist the floor in integrity-protected persistent storage (/data, ideally a TPM NV counter as in the OS OTA design) and ratchet it after each successful install. Express rollback authorization as a signed manifest field checked by the verifier, and remove the env bypass.
- **Doğrulama:** Rust unit tests for the downgrade matrix including pre-releases. QEMU test: install v1.0.0, then attempt v1.0.0-rc.1 and v0.9.0 and expect refusal; reboot or slot-switch and expect the floor to persist.

<a id="EI-040"></a>

### EI-040 — Lockdown is an optional env knob; skipping it still reports a successful install

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install / etc/suderra/edge-install.env
- **Köken:** doğrulanan iddia T78 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:18`, `board/suderra/common/rootfs-overlay/etc/suderra/edge-install.env:17`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:18 default 1; :137 overridden by SUDERRA_LOCKDOWN_AFTER_INSTALL from the sourced config; :303-316 skips lockdown with only an echo
  - board/suderra/common/rootfs-overlay/etc/suderra/edge-install.env:17 SUDERRA_LOCKDOWN_AFTER_INSTALL="1" (root-owned; writable inside the worker sandbox, which has /etc/suderra in ReadWritePaths)
  - suderra-provision-worker:51-53 writes status=ok "edge install completed" whether or not lockdown ran, so the cloud cannot tell an unlocked device from a locked one
- **Kök neden:** A security-critical state transition is controlled by a mutable shell variable, and the provisioning result does not carry the lock state.
- **Mimari düzeltme yönü:** Remove the knob from non-dev variants: lockdown becomes mandatory by build-time variant, or a signed manifest field may request a lab exception that the verifier honours only on dev builds. The provisioning result carries an explicit lockdown_state that the cloud must check.
- **Doğrulama:** Contract test: suderra-edge-install has no lockdown-skip path when VARIANT is not dev. A worker result-schema test asserts lockdown_state is present.

<a id="EI-041"></a>

### EI-041 — Lock state is a marker file on mutable, agent-owned storage that picks the firewall profile; prod never creates it and keeps 22/tcp open

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-firewall / suderra-provision-worker / prod post-build
- **Köken:** doğrulanan iddia T79 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-firewall:4-8`, `board/suderra/common/post-build.sh:228-286`, `package/suderra-edge-agent/suderra-edge-agent.mk:49`, `board/suderra/common/rootfs-overlay/etc/systemd/system/nftables.service:21`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-firewall:4-8 chooses nftables.conf only if /var/lib/suderra/.appliance-locked exists; otherwise nftables.provisioning.conf (:20 accepts tcp dport 22)
  - suderra-provision-worker:23 uses the same marker as its lock check; only suderra-lockdown:96 creates it
  - board/suderra/common/post-build.sh:228-286 the prod lockdown path masks units but never selects the appliance ruleset or creates the marker (it cannot: /var/lib/suderra is meant to be /data)
  - /var/lib/suderra is owned by the agent user (suderra-data-unlock:22; suderra-edge-agent.mk:49), so a compromised agent can delete the marker and revert the device to the provisioning firewall
  - Related: nftables.service:21 CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW (no CAP_DAC_READ_SEARCH), so root cannot even stat the marker in a 200:200 0750 directory and the provisioning ruleset loads (see incidental)
- **Kök neden:** The appliance or provisioning mode is runtime state inferred from a file in the least-trusted principal's directory, instead of a build-time property (prod) or an integrity-protected state.
- **Mimari düzeltme yönü:** For prod, ship only the appliance ruleset; do not install nftables.provisioning.conf at all. For provisioning images, represent mode as root-owned, integrity-protected state (a root-only dir declared in tmpfiles, ideally TPM NV or a signed record), selected by systemd targets or conditions (provisioning.target vs appliance.target) rather than an ad-hoc file test.
- **Doğrulama:** Image contract: prod rootfs contains no nftables.provisioning.conf and no port-22 accept. QEMU: a locked device, after reboot and after the agent user deletes files in its home, still has no 22 accept in `nft list ruleset`.

<a id="EI-042"></a>

### EI-042 — Three diverging copies of suderra-agent.service; the untested overlay copy is the effective one and grants /dev/watchdog

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-agent.service (3 copies)
- **Köken:** doğrulanan iddia T81 (CONFIRMED)
- **Kanıt (dosya:satır):** `aquaculture_platform/sens-api-gateway/systemd/suderra-agent.service:33`, `package/suderra-edge-agent/suderra-agent.service:6`, `package/suderra-edge-agent/suderra-edge-agent.mk:36-38`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:4-7`, `board/suderra/common/post-build.sh:146-171`, `tests/image-contracts/edge-agent-unit-contract-test.sh:15`
- **Kanıt (ayrıntı):**
  - aquaculture_platform sens-api-gateway/systemd/suderra-agent.service:33 Requires=time-sync.target, :37 ExecStart=/usr/local/bin/suderra-agent, :95 ReadOnlyPaths=/etc/suderra, :163 DeviceAllow=/dev/watchdog, no SUDERRA_CONFIG (agent then defaults to /etc/suderra/config.yaml, src/main.rs:247-255)
  - package/suderra-edge-agent/suderra-agent.service:6 Requires=time-sync.target, :70-73 comment says /dev/watchdog is deliberately absent; installed to /usr/lib/systemd/system (suderra-edge-agent.mk:36-38)
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:4-7 no Requires, :69 DeviceAllow=/dev/watchdog rw. /etc/systemd/system takes precedence over /usr/lib, and post-build.sh:146-171 enables the /etc copy (seen in the built qemu image's multi-user.target.wants)
  - tests/image-contracts/edge-agent-unit-contract-test.sh:15 checks only package/suderra-edge-agent/suderra-agent.service; no test checks the overlay or effective unit
  - Practical impact is limited, because /dev/watchdog is root 0600 and uid 200 cannot open it anyway (see T84), but the documented security invariant is false
- **Kök neden:** The unit file is copy-pasted across repos and layers with no single source, and the contract test targets a file that is not the one systemd loads.
- **Mimari düzeltme yönü:** Keep one unit source, versioned with the agent (sens-api-gateway) and consumed by the OS package. Delete the overlay copy. Point the contract test at the effective unit in the final rootfs (resolve /etc over /usr/lib) and fail if more than one suderra-agent.service exists.
- **Doğrulama:** Image contract test on rootfs.ext2: exactly one suderra-agent.service exists, it has no /dev/watchdog DeviceAllow, and `systemd-analyze verify` passes.

<a id="EI-043"></a>

### EI-043 — x86_64 industrial kernel has no USB host, USB-serial, I2C/SMBus or GPIO drivers and no microcode delivery

- **Önem:** Orta · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86_64 kernel hardware coverage
- **Köken:** doğrulanan iddia T95 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/x86_64/linux-x86_64.config:1-206`, `configs/suderra_x86_64_defconfig:4-13`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/linux-x86_64.config:1-206 - no CONFIG_USB, USB_XHCI_HCD, USB_EHCI, USB_STORAGE, USB_SERIAL*, I2C, I2C_I801, GPIOLIB, MMC
  - linux 6.12 drivers/usb/Kconfig:29-32 - USB_SUPPORT (menu) defaults y, but :44-46 CONFIG_USB (host core) has no default, so there is effectively no USB host
  - linux 6.12 arch/x86/Kconfig:1333-1335 - MICROCODE is def_bool y, but no BR2_PACKAGE_INTEL_MICROCODE is set and there is no initrd (T94), so no microcode is ever loaded
  - configs/suderra_x86_64_defconfig:4-13 - header promises industrial PCs (Advantech/Siemens/Kontron)
- **Kök neden:** The kernel config was sized for QEMU virtio plus a few NICs. There is no hardware-support matrix for the target industrial PCs that drives kernel options.
- **Mimari düzeltme yönü:** Create a board/x86 hardware-support fragment derived from a target-PC matrix: USB core/XHCI/EHCI/storage/HID, USB_SERIAL_FTDI_SIO/CP210X/CH341/PL2303, CDC_ACM, I2C_I801, GPIO_ICH/pinctrl, MMC_SDHCI_PCI/ACPI, 8250_DW/MFD_INTEL_LPSS. Add intel-microcode with early loading (initramfs or CONFIG_EXTRA_FIRMWARE). Add a contract test per supported PC model.
- **Doğrulama:** QEMU with -device qemu-xhci plus usb-serial and usb-storage: devices enumerate. Hardware lab per supported IPC: lsusb, an RS485 adapter loopback, and dmesg showing a microcode revision update.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Confirmed by the simulation: CONFIG_USB, I2C, GPIOLIB and MMC are all unset, and only MICROCODE=y. Downgraded because it is a functional hardware-coverage gap that shows up at the first hardware bring-up, with no security impact. On-board 8250 COM ports (SERIAL_8250 and 8250_PCI built in), SATA/AHCI and NVMe are supported, which covers the common IPC Modbus-RTU and storage paths. BIOS normally supplies CPU microcode. USB-serial adapters and eMMC IPCs are the real losses.

<a id="EI-044"></a>

### EI-044 — /data unlock failure is silent: boot continues, the agent condition-skips, and dev mounts /data by a spoofable label

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** /data service ordering
- **Köken:** doğrulanan iddia T101 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-data.service:1-20`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:4-7`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:27-37`
- **Kanıt (ayrıntı):**
  - rootfs-overlay/etc/systemd/system/suderra-data.service:1-20 - no FailureAction/OnFailure/SuccessAction; WantedBy=sysinit.target (Wants semantics)
  - rootfs-overlay/etc/systemd/system/suderra-agent.service:4-7 - no Requires=/BindsTo=suderra-data.service; ConditionPathExists=/var/lib/suderra/config/config.yaml makes the agent silently 'condition failed', not failed
  - rootfs-overlay/usr/sbin/suderra-data-unlock:27-37 - dev: mount -L SUDERRA-DATA (any USB stick with that label wins)
  - suderra-data-unlock:89 - prod uses /dev/disk/by-partlabel/data, with the same first-match ambiguity
- **Kök neden:** Mutable state was treated as optional, and device identity is resolved by name instead of being bound to the boot disk.
- **Mimari düzeltme yönü:** suderra-data.service: OnFailure=suderra-data-failed.target (alarm LED/telemetry plus a defined safe state), FailureAction per policy. Agent: Requires=/After=suderra-data.service and RequiresMountsFor=/var/lib/suderra. Resolve /data by PARTUUID or disk GUID from the same disk as the booted root, passed via the signed cmdline.
- **Doğrulama:** QEMU: remove the TPM and assert the device enters the defined failure state with an alarm (not a silent 'running'). Insert a USB stick labelled SUDERRA-DATA (dev) or PARTLABEL data and assert it is ignored.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Accurate: no OnFailure/FailureAction, the agent has no Requires= on suderra-data, and its ConditionPathExists skips it silently. The impact is fail-safe, though. The agent does not run on a missing /data, and the cloud sees a missing heartbeat. The prod partlabel 'spoof' leads only to DoS: a foreign LUKS has no TPM token and fails, a blank one gets formatted with a TPM-sealed key, and a non-LUKS one is refused (suderra-data-unlock:49-52). Label spoofing that leads to attacker-controlled config applies only to dev images, which are already physically open (dropbear, getty).

<a id="EI-045"></a>

### EI-045 — RPi4/CM4 and RevPi Connect 4 share RAUC compatible=suderra-os-aarch64

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** RAUC compatible
- **Köken:** doğrulanan iddia T104 (CONFIRMED)
- **Kanıt (dosya:satır):** `package/suderra-rauc-config/system.conf.arm:2`, `package/suderra-rauc-config/suderra-rauc-config.mk:16-18`, `scripts/create-rauc-bundle.sh:231`, `ci/evidence-contract.yml:690`
- **Kanıt (ayrıntı):**
  - package/suderra-rauc-config/system.conf.arm:2 compatible=suderra-os-aarch64 (one file for every aarch64 board, suderra-rauc-config.mk:16-18)
  - scripts/create-rauc-bundle.sh:231 - every ARM bundle has compatible=suderra-os-aarch64
  - ci/evidence-contract.yml:690,714 - rpi4-prod-ab and revpi4-prod-ab both suderra-os-aarch64 (x86 hardware and qemu-prod-ab likewise share suderra-os-x86_64 at :636,:738)
- **Kök neden:** Compatible strings are keyed by architecture rather than by board image identity.
- **Mimari düzeltme yönü:** Generate the compatible from the board identity SSoT (suderra-os-revpi-connect4, suderra-os-rpi4-cm4, suderra-os-x86-ipc, suderra-os-qemu-x86-prodab) for both system.conf and the bundle manifest from one place.
- **Doğrulama:** Contract test: the system.conf compatible equals the bundle compatible for each target, and all are unique across targets. QEMU/hardware: installing an rpi4 bundle on RevPi is rejected by RAUC.

<a id="EI-046"></a>

### EI-046 — Nothing gates time-sync.target, there is no RTC, and time-dependent security runs on the build-epoch clock until NTP

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** time synchronisation
- **Köken:** doğrulanan iddia T105 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/post-build.sh:138-139`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:4-5`, `board/suderra/aarch64-rpi4/config.txt:118-119`, `board/suderra/aarch64-rpi4/config-uboot.txt:123-124`, `userspace/suderra-ota/src/main.rs:428-433`
- **Kanıt (ayrıntı):**
  - board/suderra/common/post-build.sh:138-139 - only chrony.service enabled; no chrony-wait
  - buildroot/package/chrony/chrony.service - no Before=time-sync.target; chrony-wait.service (examples/) is not installed (chrony.mk:76-88)
  - rootfs-overlay/etc/systemd/system/suderra-agent.service:4-5 - After=time-sync.target without Wants=, so the ordering is a no-op
  - board/suderra/aarch64-rpi4/config.txt:118-119 and config-uboot.txt:123-124 - RTC overlay commented out
  - userspace/suderra-ota/src/main.rs:428-433,843-852 - manifest expiry uses the system clock
- **Kök neden:** Time is assumed rather than modelled as a boot dependency, and boards have no time source policy.
- **Mimari düzeltme yönü:** Install and enable chrony-wait.service (Before=time-sync.target, Wants=time-sync.target) and make time-sensitive services Wants=time-sync.target with a bounded timeout and an explicit 'time-untrusted' degraded mode. Enable board RTCs in the boot DTB (RevPi Connect 4 RTC, CM4-IO PCF85063A). Use authenticated NTP (NTS) or the cloud's signed time.
- **Doğrulama:** QEMU without network: the agent must not start its TLS/telemetry paths (or must report time-untrusted). With network: time-sync.target is reached only after chronyc waitsync succeeds. Hardware: RTC holds time across a power cycle.

<a id="EI-047"></a>

### EI-047 — No defined procedure to take Secure Boot ownership (PK/KEK/db) on Windows-shipped industrial PCs; GRUB is signed only with the Suderra db key and there is no shim

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** x86 Secure Boot ownership
- **Köken:** doğrulanan iddia T113 (CONFIRMED)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:494-529`, `scripts/production-artifacts.sh:445-492`, `docs/architecture/boot-chain.md:10-15`
- **Kanıt (ayrıntı):**
  - scripts/production-artifacts.sh:494-529 - build_signed_grub sbsigns GRUB directly with SUDERRA_SECUREBOOT_SIGNING_KEY; no shim/MOK artifacts anywhere
  - production-artifacts.sh:445-492 - UKIs signed with the same key
  - the .github/workflows/secureboot-enroll.yml flow (lines 1-80) only enrolls throwaway PK/KEK/db into an OVMF varstore
  - docs/architecture/boot-chain.md:10-15,129-130 and ADR-0005:30,84-126 describe shim/MOK/OEM coordination that the code does not implement (doc/code contradiction)
  - docs/security/security-gaps-and-risks.md HW-4 - 'nothing enforces db enrollment on shipped hardware'
  - docs/operations/install.md - only manual dd; no Windows wipe or Setup Mode/key-enrolment procedure
- **Kök neden:** Secure Boot was proven only in QEMU, where the varstore is fully under control. The field ownership problem (MS-owned PK, Windows bootloaders, firmware passwords) was left to an undefined out-of-band step.
- **Mimari düzeltme yönü:** Define a mandatory factory/installer flow: the installer image boots (MS-signed shim + Suderra MOK, or Setup Mode), verifies firmware state, wipes Windows/ESP, enrolls the Suderra PK/KEK/db (keeping or removing MS UEFI CA per a documented policy for option ROMs), sets a firmware admin password, and records a TPM-quoted attestation of the SB variables. The installer refuses to finish unless SB is on with the Suderra db and the MS Windows CA removed.
- **Doğrulama:** OVMF with Microsoft keys pre-enrolled (simulating a Windows PC): run the installer and assert the final varstore contains the Suderra PK/db, a Windows bootmgr fails to boot, the Suderra UKI boots, and attestation shows PCR7 matching the expected policy. Repeat on each supported IPC model in the lab.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Confirmed: there is no shim or MOK artifact, and the installer does no Secure Boot or EFI-variable handling. Enrollment exists only for OVMF (scripts/qemu/enroll-secureboot-vars), while ADR-0005 and boot-chain.md describe MOK/OEM flows the code lacks. It is a deployment-process gap on an unreleased target. The repo's own risk register rates it Orta (Medium) and GATED as HW-4, and it causes no exposure until x86 prod ships.

<a id="EI-048"></a>

### EI-048 — ARM kernel loads modules without enforced signatures and lockdown is not forced

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM kernel config
- **Köken:** doğrulanan iddia T89 (PARTIAL)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/linux-rpi4-hardening.config:11-16`, `board/suderra/aarch64-rpi4/linux-rpi4.config:270-273`, `board/suderra/aarch64-rpi4/cmdline.txt:1`, `board/suderra/aarch64-revpi4/cmdline.txt:1`, `scripts/production-artifacts.sh:576`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/linux-rpi4-hardening.config:11-16 - monolithic kernel and FORCE_CONFIDENTIALITY explicitly deferred; :19-20 lockdown LSM compiled but no forced mode; :30 CONFIG_LSM includes lockdown
  - board/suderra/aarch64-rpi4/linux-rpi4.config:270-273 - MODULE_SIG_FORCE only as a comment
  - linux 6.12 security/lockdown/Kconfig:1-4 - SECURITY_LOCKDOWN_LSM 'select MODULE_SIG if MODULES', so MODULE_SIG is auto-selected (the claim 'without MODULE_SIG' is inaccurate). MODULE_SIG_FORCE is off and the key is auto-generated per build.
  - board/suderra/aarch64-rpi4/cmdline.txt:1 and aarch64-revpi4/cmdline.txt:1 (dev) - no lockdown=
  - scripts/production-artifacts.sh:576 - prod FIT cmdline has lockdown=confidentiality, but U-Boot never passes FIT bootargs (see T88)
- **Kök neden:** The ARM kernel fragment is shared between dev and prod and depends on the bcm2711 module set. Enforcement was postponed to hardware gate G4 rather than put in a prod-only fragment.
- **Mimari düzeltme yönü:** Prod-only kernel fragment: MODULE_SIG_FORCE=y, MODULE_SIG_ALL=y, MODULE_SIG_SHA512, LOCK_DOWN_KERNEL_FORCE_INTEGRITY (or CONFIDENTIALITY), with the module key from the HSM/ephemeral per-build key discarded after signing. Better: build the BCM2711/RevPi driver set built-in and disable CONFIG_MODULES. Assert against the final .config, not the fragment.
- **Doğrulama:** CI: parse output/build/linux-*/.config of the prod build and fail if MODULES=y without MODULE_SIG_FORCE=y, or if no LOCK_DOWN_KERNEL_FORCE_* is set. On device: insmod an unsigned module must fail with EKEYREJECTED, and cat /sys/kernel/security/lockdown must show [integrity] or [confidentiality].
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Factually correct: no MODULE_SIG_FORCE and no LOCK_DOWN_KERNEL_FORCE_*. But the severity mostly comes from T88. SECURITY_LOCKDOWN_LSM selects MODULE_SIG, and MODULE_SIG_ALL defaults to y. Once lockdown is active, module_sig_check rejects unsigned modules even without SIG_FORCE. The prod cmdline already carries lockdown=confidentiality and 'lockdown' is in CONFIG_LSM. So when the signed bootargs actually reach the kernel, unsigned modules are refused. The leftover issue is that enforcement depends on the cmdline instead of being compiled in. That is defense in depth, and ADR-0007 M3 tracks it.

<a id="EI-049"></a>

### EI-049 — ARM cmdline lacks module.sig_enforce/debugfs=off and the kernel/firmware/U-Boot console shares ttyAMA0 with Modbus-RTU

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM cmdline / UART allocation
- **Köken:** doğrulanan iddia T90 (CONFIRMED)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:570-577`, `board/suderra/aarch64-rpi4/config.txt:47-48`, `board/suderra/aarch64-rpi4/config-uboot.txt:52-53`, `board/suderra/aarch64-revpi4/cmdline.txt:1`, `board/suderra/aarch64-rpi4/cmdline.txt:1`, `board/suderra/aarch64-rpi4/config.txt:91`, `scripts/production-artifacts.sh:575`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:67`, `aquaculture_platform/sens-api-gateway/systemd/suderra-agent.service:148`
- **Kanıt (ayrıntı):**
  - scripts/production-artifacts.sh:570-577 - ARM tail has no module.sig_enforce=1 and no debugfs=off; compare the x86 tail at :273
  - board/suderra/aarch64-rpi4/config.txt:47-48 and config-uboot.txt:52-53 - enable_uart=1, uart_2ndstage=1
  - board/suderra/aarch64-revpi4/cmdline.txt:1 and aarch64-rpi4/cmdline.txt:1 - console=serial0,115200 (serial0 is ttyAMA0 with dtoverlay=disable-bt, config.txt:91); prod console=ttyAMA0 at production-artifacts.sh:575
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service:67 DeviceAllow=/dev/ttyAMA0; aquaculture_platform/sens-api-gateway/systemd/suderra-agent.service:148 says '/dev/ttyAMA0 PL011 UART for Modbus-RTU on RPi'
  - U-Boot BOOTDELAY=2 on the same serial line (boot/Kconfig:1495-1497): any RS485 traffic during boot aborts autoboot
- **Kök neden:** Console/debug convenience ('serial console is mandatory for field diagnosis', config.txt:45-46) was set without a UART allocation contract shared with the agent's fieldbus use.
- **Mimari düzeltme yönü:** Define a per-board UART allocation SSoT, consumed by both OS and agent: fieldbus UARTs are never consoles. Prod: no serial console (console=tty1 or none, uart_2ndstage=0, U-Boot silent with BOOTDELAY=-2), or a dedicated debug UART that is not wired to RS485. Add module.sig_enforce=1 and debugfs=off to the ARM prod cmdline once T89 lands.
- **Doğrulama:** Contract test: the console= device from the generated FIT cmdline must not appear in the agent's allowed fieldbus device list. Hardware test: run a Modbus master flooding ttyAMA0 during a power cycle and assert the device boots and the link has no stray console bytes.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Partly true, but narrower than claimed. On prod, serial-getty@ is masked (post-build.sh:246-267), so no getty fights the agent for ttyAMA0. Kernel output on that line is limited by quiet loglevel=3, and the prod cmdline is not even delivered (T88). On RevPi Connect 4 the RS485 port is UART5 and the debug port is UART1, not ttyAMA0/UART0. The conflict is therefore real only on Pi4/CM4 with an RS485 HAT on GPIO14/15: firmware, U-Boot and kernel-error output go onto the bus, and stray RX can stop the 2s autoboot. module.sig_enforce is redundant once lockdown is active (see T89).

<a id="EI-050"></a>

### EI-050 — dm-verity table has no corruption policy, and partitions are taken from the first PARTLABEL match

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** verity initramfs
- **Köken:** doğrulanan iddia T97 (CONFIRMED)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:421`, `scripts/production-artifacts.sh:403-416`
- **Kanıt (ayrıntı):**
  - scripts/production-artifacts.sh:421 - table '0 sectors verity 1 root hash bs bs blocks start sha256 roothash salt' with no optional args (no restart_on_corruption/panic_on_corruption/ignore_zero_blocks)
  - scripts/production-artifacts.sh:403-416 - blkid -t PARTLABEL=<label> -o device | head -n 1 picks the first match from any disk, including USB
  - Integrity is still bound by the root hash, so injection is DoS/confusion only, not code execution
- **Kök neden:** The initramfs is a minimal hand-written script. Device identity was never bound to the boot disk, and runtime corruption handling was not considered.
- **Mimari düzeltme yönü:** Add 'restart_on_corruption' (or panic_on_corruption with panic=10) so corruption becomes a reboot, which with T96 fixed falls back to the other slot. Resolve partitions only on the disk the bootloader booted from: compare the GPT disk GUID or PARTUUID embedded in the signed cmdline (suderra.verity.root_partuuid=...) instead of PARTLABEL.
- **Doğrulama:** QEMU: flip a byte in rootfs-a after boot, read the file, assert a reboot plus slot fallback. Attach a second disk with duplicate PARTLABELs and assert boot still uses the original disk (or refuses).

<a id="EI-051"></a>

### EI-051 — x86 kernel tarball (6.12.6) is not hash-enforced; forced hash checking is enabled only on ARM defconfigs

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** build supply chain
- **Köken:** doğrulanan iddia T98 (CONFIRMED)
- **Kanıt (dosya:satır):** `configs/suderra_x86_64_defconfig:35-37`
- **Kanıt (ayrıntı):**
  - configs/suderra_x86_64_defconfig:35-37 and suderra_qemu_x86_64_prod_ab_defconfig:29-31 - custom 6.12.6; no BR2_DOWNLOAD_FORCE_CHECK_HASHES or BR2_GLOBAL_PATCH_DIR
  - BR2_DOWNLOAD_FORCE_CHECK_HASHES=y only in configs/suderra_aarch64_{rpi4,revpi4}*_defconfig and usb_installer (lines 15-16/38-39/42-43)
  - buildroot/linux/linux.hash:3 has only linux-6.12.51; board/suderra/buildroot-hashes/linux/linux.hash covers only the raspberrypi tarball
  - Without the forced check, Buildroot warns 'no hash' and builds anyway
- **Kök neden:** Hash pinning was added per board during ARM work instead of as a global build policy.
- **Mimari düzeltme yönü:** Make it automatic: one shared defconfig fragment (or a validate-build-matrix rule) that requires BR2_DOWNLOAD_FORCE_CHECK_HASHES=y and BR2_GLOBAL_PATCH_DIR on every defconfig. Add a linux-6.12.x.tar.xz hash, ideally after moving x86 to the Buildroot-hashed 6.12.51.
- **Doğrulama:** scripts/ci/validate-build-matrix.py check: fail if any defconfig lacks FORCE_CHECK_HASHES. Build with a corrupted dl/linux tarball must fail.

<a id="EI-052"></a>

### EI-052 — chrony is built without NTS and ships the example config (pool.ntp.org, makestep 1.0 3, drift on read-only /var), while the agent's ChronyNtsClockAuthority assumes NTS

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** buildroot chrony package / chrony.conf
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/nftables.conf:52-53`, `aquaculture_platform/sens-api-gateway/src/main.rs:2190-2198`
- **Kanıt (ayrıntı):**
  - buildroot/package/chrony/chrony.mk:56-60 --without-gnutls unless BR2_PACKAGE_GNUTLS (set by no defconfig); :78 installs examples/chrony.conf.example2
  - output/suderra_qemu_x86_64_defconfig/target/etc/chrony.conf: 'pool pool.ntp.org iburst', 'makestep 1.0 3', 'driftfile /var/lib/chrony/drift' (read-only /var in prod)
  - rootfs-overlay/etc/nftables.conf:52-53 allows udp 123 to any destination
  - aquaculture_platform/sens-api-gateway/src/main.rs:2190-2198 ChronyNtsClockAuthority only reads the chronyc tracking age
- **Kök neden:** Time trust was never specified end to end between OS and agent.
- **Mimari düzeltme yönü:** Ship a Suderra chrony.conf (NTS servers from signed config, authselectmode require), build chrony with gnutls, persist chrony state on /data, and have the agent verify NTS-authenticated source selection.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-053"></a>

### EI-053 — The installer resolves its cosign verifier from COSIGN_BINARY or PATH with no production lock, cosign is not shipped, and the error text suggests curl-installing "latest"

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** userspace/suderra-installer verify.rs
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/verify.rs:83-104`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/verify.rs:83-104 COSIGN_BINARY env, else PATH search; the error text tells users to curl releases/latest/download/cosign
  - No BR2 package installs cosign in any defconfig
- **Kök neden:** Signature verification is delegated to an external, environment-resolved tool.
- **Mimari düzeltme yönü:** Verify in-process with a pinned Rust implementation and a key from the verity rootfs; never resolve verifiers from env/PATH in release builds.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-054"></a>

### EI-054 — The signed edge manifest is canonicalized by re-serializing the parsed Rust struct (unknown fields dropped unsigned, chrono re-formatting), and verification uses non-strict Ed25519 verify

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** userspace/suderra-installer contracts.rs
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/contracts.rs:856-862`, `userspace/suderra-installer/src/contracts.rs:97-116`, `userspace/suderra-installer/src/contracts.rs:847-849`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/contracts.rs:856-862 canonical_without_signature = serde_json::to_value(struct) minus signature; :864-900 custom sorted-key writer
  - contracts.rs:97-116 no deny_unknown_fields, so unknown fields are silently dropped and unsigned; Option config is re-emitted as null; chrono DateTime fields are re-formatted
  - contracts.rs:847-849 verify_ed25519 uses key.verify, not verify_strict, while the agent enforces verify_strict as an invariant (sens-api-gateway Cargo.toml [[test]] deploy_verify_strict)
- **Kök neden:** There is no written canonicalization spec, so the signed bytes are whatever the Rust structs serialize to, which a TypeScript signer cannot reproduce reliably.
- **Mimari düzeltme yönü:** Specify RFC 8785 JCS over the received JSON (or a detached raw-bytes envelope), add deny_unknown_fields and verify_strict, and publish cross-language golden signing vectors.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-055"></a>

### EI-055 — Install rollback restores only the current link: config.yaml is overwritten before activation and never restored, and a failed first install leaves the new agent enabled

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-edge-install rollback
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:276`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:276 config.yaml is replaced before activation
  - suderra-edge-install:292-300 and :304-312 rollback touches only the current link, so the old binary restarts with the new config; on a first install there is no stop or disable (:291 enable already done)
- **Kök neden:** The install is not modelled as an atomic transaction over binary pointer, config and unit enablement.
- **Mimari düzeltme yönü:** Stage config and binary together under the release directory and switch both with one pointer; on rollback switch the pointer and stop/disable as needed; fault-injection test restoring pre-install state.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-056"></a>

### EI-056 — Kernel hardening intent is silently overridden by Buildroot fixups: systemd forces CONFIG_USER_NS=y despite both fragments disabling it, and CONFIG_GCC_PLUGIN_STACKLEAK is dropped because Buildroot disables GCC_PLUGINS

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** kernel fragments vs Buildroot linux/systemd fixups
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/kernel-fragment.config:54`, `board/suderra/aarch64-rpi4/linux-rpi4-hardening.config:54-56`, `board/suderra/common/rootfs-overlay/etc/sysctl.d/90-suderra-hardening.conf:7-11`, `board/suderra/x86_64/linux-x86_64.config:23`
- **Kanıt (ayrıntı):**
  - buildroot/package/systemd/systemd.mk:870 KCONFIG_ENABLE_OPT CONFIG_USER_NS (unconditional, applied after fragment merge per buildroot/package/pkg-kconfig.mk:177)
  - board/suderra/common/kernel-fragment.config:54 and aarch64-rpi4/linux-rpi4-hardening.config:54-56 disable USER_NS
  - rootfs-overlay/etc/sysctl.d/90-suderra-hardening.conf:7-11 claims 'already off in prod kernels'; only sysctl max_user_namespaces=0 mitigates
  - board/suderra/x86_64/linux-x86_64.config:23 CONFIG_GCC_PLUGIN_STACKLEAK=y, but buildroot/linux/linux.mk:476 KCONFIG_DISABLE_OPT CONFIG_GCC_PLUGINS
- **Kök neden:** Hardening intent is checked in fragments, not in the effective .config after Buildroot fixups.
- **Mimari düzeltme yönü:** Assert hardening properties on the final .config in CI (kconfig-hardened-check), and either accept USER_NS=y with the sysctl mitigation documented or override the fixup; use plugin-independent alternatives to STACKLEAK.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-057"></a>

### EI-057 — Spool IPC race: the worker fires on any inbox change and can claim a manifest still being streamed from SSH stdin, so verification fails intermittently

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-provision / suderra-provision-worker(.path)
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-provision-worker.path:6`
- **Kanıt (ayrıntı):**
  - suderra-provision-worker.path:6 PathModified=/var/spool/suderra-provision/inbox fires on IN_CREATE/IN_MODIFY of any entry
  - suderra-provision:52 `cat > inbox/manifest.json` streams from SSH stdin; :61 the trigger file is written last but never used as a gate
  - suderra-provision-worker:37-46,57-59 claims (mv) the file as soon as it is non-empty, so the remaining stream lands in the moved inode after verification starts
- **Kök neden:** The file-drop protocol has no atomic publish step; the trigger file is written but never used as a gate.
- **Mimari düzeltme yönü:** Write to a temp name and rename atomically into the inbox, trigger only on the commit marker, or replace the spool with a socket-activated request/response service.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-058"></a>

### EI-058 — The root-password guardrail treats an empty shadow field (passwordless login) as "locked — safe", and checks only root

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** board/suderra/common/post-build.sh root credential guardrail
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/post-build.sh:294-298`
- **Kanıt (ayrıntı):**
  - board/suderra/common/post-build.sh:294-298 case ""|"*"|"!"|"!!"|"!"*) : # locked — safe
  - buildroot system/Config.in:365-375 an empty BR2_TARGET_GENERIC_ROOT_PASSWD with BR2_TARGET_ENABLE_ROOT_LOGIN=y means 'root will need no password to log in'; dev images run a serial getty (boot-test.serial.log shows 'suderra-edge login:')
  - The guard checks only root, not provision or other accounts
  - Currently masked: buildroot/package/skeleton-init-common/skeleton-init-common.mk:75-79 sets root:* when ENABLE_ROOT_LOGIN is unset
- **Kök neden:** The empty-field semantics of shadow(5) were inverted in the allow-list.
- **Mimari düzeltme yönü:** Treat "" as a hard failure for every account in TARGET_DIR/etc/shadow and accept only "*", "!" or "!"-prefixed fields; unit-test the guard with fixture shadow files.
- **Not:** Incidental finding (merged from 3 raw report(s)); area=os.

<a id="EI-059"></a>

### EI-059 — Egress open on fixed ports to any destination, no DHCP rule, and agent protocols blocked; static rules cannot be customised per site

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** nftables appliance policy
- **Köken:** doğrulanan iddia T106 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/nftables.conf:42-66`, `aquaculture_platform/sens-api-gateway/src/plc_programming/s7comm.rs:41`, `aquaculture_platform/sens-api-gateway/src/plc_programming/ads.rs:43`, `aquaculture_platform/sens-api-gateway/src/plc_programming/ethernet_ip.rs:41`, `aquaculture_platform/sens-api-gateway/src/plc_programming/codesys.rs:43`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-firewall:4-10`, `aquaculture_platform/sens-api-gateway/src/commands/plc/upload.rs:131`, `aquaculture_platform/sens-api-gateway/src/commands/ide_deploy.rs:104-107`
- **Kanıt (ayrıntı):**
  - rootfs-overlay/etc/nftables.conf:42-66 - udp/tcp 53, udp 123, tcp 443/8883/502/4840 to any address (the comment at :42-46 admits it)
  - nftables.conf - no udp 67/68 rule (DHCP renewals over UDP sockets are dropped; only raw-socket DISCOVER/REBIND bypass the hook)
  - agent ports blocked: sens-api-gateway/src/plc_programming/s7comm.rs:41 (102), ads.rs:43 (48898), ethernet_ip.rs:41 (44818), codesys.rs:43 (1217), config.rs:442/2916 MQTT 1883 default
  - nftables.conf input chain :11-26 - drops all new inbound, including the agent's own OPC UA/SCADA servers
  - rootfs-overlay/usr/sbin/suderra-firewall:4-10 - picks one of two static files in /etc on the verity rootfs; no site-specific sets
- **Kök neden:** The firewall was written independently of the agent's protocol inventory and the site's network data. There is no SSoT linking agent capabilities, ports and destinations.
- **Mimari düzeltme yönü:** Generate the ruleset from a signed site policy delivered with the agent config (named sets: cloud endpoints, PLC subnets/ports, NTP/DNS servers), loaded from /data after signature verification, with a static default-deny base in the image. Derive allowed protocol ports from the agent's enabled drivers in that signed config. Add DHCP client rules.
- **Doğrulama:** QEMU: with a site policy allowing PLC 10.0.0.0/24:102, S7 to that subnet works and 443 to a non-allowlisted IP is dropped. DHCP lease renewal succeeds over 2x lease time. Contract test: every agent driver default port has a policy mapping.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): Partly inaccurate. The MQTT default is 8883, not 1883: config.rs:2915-2917 default_mqtt_port() returns 8883, and the 1883 at :442 is only a doc comment. 8883 is allowed. The blocked ports (102, 48898, 44818, 1217) belong to the optional plc_programming (ST upload) module. The core paths (443, 8883, Modbus/TCP 502, OPC UA 4840) are allowed. Per the claim's own reasoning, DHCP renew over the UDP socket is dropped but the raw-socket rebind at T2 keeps the lease. What remains: open egress to any destination (admitted at nftables.conf:42-46), no per-site policy, and blocked optional PLC protocols.

<a id="EI-060"></a>

### EI-060 — Published release images are dev variants with ephemeral CI trust roots

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** release pipeline
- **Köken:** doğrulanan iddia T108 (CONFIRMED)
- **Kanıt (dosya:satır):** `ci/build-matrix.yml:10-46`, `configs/suderra_aarch64_rpi4_defconfig:37`, `board/suderra/aarch64-rpi4/config.txt:19`, `board/suderra/common/post-build.sh:188-198`, `.github/workflows/image-build.yml:97-101`, `scripts/ci/prepare-ci-keyring.sh:1-6`
- **Kanıt (ayrıntı):**
  - ci/build-matrix.yml:10-46 (qemu_x86_64 dev, release:true), :162-198 (rpi4 dev, release:true), :200-241 (usb_installer, release:true), :244-279 (revpi4 dev, release:true); all prod_ab/x86 rows release:false
  - configs/suderra_aarch64_rpi4_defconfig:37,154,193 and revpi4_defconfig:14,92,107 - VARIANT_DEV, dropbear, getty; config.txt:19 kernel=Image (no signed boot)
  - post-build.sh:188-198 - dev enables firstboot/dropbear/provision worker
  - .github/workflows/image-build.yml:97-101 - scripts/ci/prepare-ci-keyring.sh; prepare-ci-keyring.sh:1-6,92-106,178-188 - RAUC/verity certs generated per run, valid 14 days
  - package/suderra-keys/suderra-keys.mk - the CI rauc-signing.crt is installed as /etc/rauc/keyring.pem in dev images
- **Kök neden:** The release pipeline grew around development artifacts while the prod lanes stayed release:false. Variant and trust root are not part of the publish gate.
- **Mimari düzeltme yönü:** Make it impossible: the publish step requires VARIANT=prod in os-release and a trust-root profile 'prod' (HSM) for every published asset. Dev/lab artifacts go to a separate, clearly named channel signed with a distinct key that prod devices never trust.
- **Doğrulama:** release-workflow contract test: extract /etc/os-release and /etc/rauc/keyring.pem from each published image and fail unless VARIANT=prod and the cert chains to the prod root. A negative test publishing a dev image must fail.
- **Not:** Adversarial re-check rated MEDIUM (verifier HIGH): True that the release:true rows are dev/lab variants with CI-ephemeral keys. The root-cause line 'variant and trust root are not part of the publish gate' is partly wrong. release.yml:97 runs candidate-readiness, which sends any non-pre-release tag to production_readiness(). That blocks the release while any production_required target has production_ready=false, which is true of all targets today. Only '-' pre-release tags get through, and they are published as prerelease with a 'lab validation only' body. Remaining risks: install.md, which targets field engineers, walks users through alpha images with default suderra/suderra SSH. And once production_ready flips, the release selector would still publish the dev rows.

<a id="EI-061"></a>

### EI-061 — Installer verifies the payload, then re-reads it from removable media (TOCTOU); a failed post-write check leaves the unverified image bootable

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** USB OS installer
- **Köken:** doğrulanan iddia T110 (CONFIRMED)
- **Kanıt (dosya:satır):** `package/suderra-os-installer/suderra-os-install:104-131`
- **Kanıt (ayrıntı):**
  - package/suderra-os-installer/suderra-os-install:104-131 - verify_payload hashes the payload on the USB
  - suderra-os-install:466 - xz -dc "${image_path}" | dd of=target re-reads from the same removable media
  - suderra-os-install:472-475 - post-write sha256 of the target catches a swap, but die() only exits, leaving the attacker image on eMMC with no wipe or invalidation
- **Kök neden:** Verification and use are separate reads of mutable media. The failure path has no 'make target unbootable' step.
- **Mimari düzeltme yönü:** Stream once: decompress and hash in the same pipeline that writes, and commit only after the hash matches. Write to the target with the boot partition zeroed or a sentinel set first, and enable the partition table or boot files only after verification. On mismatch, wipe the first and last MiB of the target.
- **Doğrulama:** Installer test (tests/installer): swap the payload file between verify and write (inotify hook). Assert the install fails and the target has no valid partition table or boot partition.

<a id="EI-062"></a>

### EI-062 — Installer security escapes (TLS off, legacy copy install) are gated by a variant check that the environment can override

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-installer
- **Köken:** doğrulanan iddia T111 (CONFIRMED)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/download.rs:129-145`, `userspace/suderra-installer/src/variant.rs:32-37`, `userspace/suderra-installer/src/cmd/install.rs:462-470`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/download.rs:129-145 - SUDERRA_INSECURE=1 disables certificate verification unless is_production()
  - userspace/suderra-installer/src/variant.rs:32-37 - SUDERRA_OS_VARIANT/SUDERRA_VARIANT env take precedence over /etc/os-release; a missing os-release returns false (fail-open) despite the 'fail-safe' module doc :13-16
  - userspace/suderra-installer/src/cmd/install.rs:462-470 - SUDERRA_ALLOW_LEGACY_COPY_INSTALL gated by the same is_production()
- **Kök neden:** Policy decisions are taken from the caller-controlled environment instead of immutable image facts.
- **Mimari düzeltme yönü:** Read the variant only from the verity-protected /etc/os-release (or a build-time constant), never from env, and treat 'unknown' as prod. Better: compile the insecure paths out of release builds (cfg(feature="lab")).
- **Doğrulama:** Unit test: SUDERRA_OS_VARIANT=dev plus a prod os-release must still forbid SUDERRA_INSECURE. Missing os-release must count as production. Release build has no 'insecure' symbol (cargo feature check).

<a id="EI-063"></a>

### EI-063 — The firstboot config skeleton uses the all-zero UUID, which fails @IsUUID('4', ...); in the designed flow that request is never sent

- **Önem:** Düşük · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-firstboot.service config skeleton vs cloud DeviceActivationRequest
- **Köken:** doğrulanan iddia T124 (PARTIAL)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:52-67`, `aquaculture_platform/apps/sensor-service/src/edge-device/dto/provisioning.dto.ts:149`, `aquaculture_platform/sens-api-gateway/src/provisioning.rs:288-296`
- **Kanıt (ayrıntı):**
  - Suderra-OS board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service:52-67 - writes device_id "00000000-0000-0000-0000-000000000000" and device_code "UNACTIVATED", owned 200:200 0600
  - apps/sensor-service/src/edge-device/dto/provisioning.dto.ts:149 - @IsUUID('4') rejects the nil UUID (its version nibble is not 4)
  - Not reachable as written: the skeleton has no provisioning_token, so the agent's activate() fails locally with NotActivated before any HTTP call (sens-api-gateway/src/provisioning.rs:288-296)
  - suderra-edge-install:275-276 overwrites config.yaml with the signed manifest's config payload, and the agent loads /etc/suderra/config.yaml anyway (config.rs:3246-3248)
  - Ownership mismatch: the skeleton is 200:200 0600 while edge-install sets root:suderra 0640 (suderra-edge-install:286-287)
- **Kök neden:** The skeleton is a placeholder that encodes 'unprovisioned' as fake identity values instead of the absence of identity, and two OS components disagree on who owns the config.
- **Mimari düzeltme yönü:** Represent unprovisioned state structurally: no agent config until a verified manifest supplies it (the agent unit already has ConditionPathExists). Drop the identity skeleton, or make device_id optional or None, with the agent refusing activation without it. Put config file ownership in one OS spec.
- **Doğrulama:** OS image contract test: after firstboot no fake device_id exists, and after install the config ownership matches the spec. Agent unit test: activation with a nil UUID fails locally with a clear error.
- **Not:** The literal mismatch is real. No production request path sends it.

<a id="EI-064"></a>

### EI-064 — Manifest version is used unvalidated as a filesystem path component and symlink target

- **Önem:** Düşük · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-installer contracts.rs / suderra-edge-install
- **Köken:** doğrulanan iddia T75 (CONFIRMED)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/contracts.rs:304`, `userspace/suderra-installer/src/contracts.rs:442`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:227`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/contracts.rs:304 ensure_nonempty("version") is the only check; compare_versions is applied to rollback_floor only (:320-324), never to version
  - contracts.rs:442 writes SUDERRA_EDGE_VERSION verbatim to the plan (shell-quoted at :501-504, so no injection)
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-edge-install:227 RELEASE_DIR="${RELEASES_DIR}/${VERSION}"; :230 mkdir -p; :265-267 install the binary there; :272 ln -sfn releases/${VERSION}. A version such as '../../../etc/systemd/system/x' escapes into a writable sandbox path
  - Exploitation requires a manifest signed with the pinned edge key, hence LOW
- **Kök neden:** The version is treated as an opaque string. Semantic validation exists in Rust only for rollback_floor, and the shell re-derives filesystem paths from untyped data.
- **Mimari düzeltme yönü:** The verifier parses manifest.version as strict SemVer, also requires version >= rollback_floor, and emits a canonical, path-safe release directory name in the plan. The shell uses only that emitted name.
- **Doğrulama:** Rust unit tests rejecting '../x', 'a/b', '1.0' and an empty pre-release, and accepting 'v1.2.3-rc.1'. A shell test asserting RELEASE_DIR always stays under RELEASES_DIR.

<a id="EI-065"></a>

### EI-065 — Fragment sets nonexistent CONFIG_SPIDEV instead of CONFIG_SPI_SPIDEV

- **Önem:** Düşük · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** ARM kernel fragment
- **Köken:** doğrulanan iddia T91 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/linux-rpi4.config:134`
- **Kanıt (ayrıntı):**
  - board/suderra/aarch64-rpi4/linux-rpi4.config:134 - CONFIG_SPIDEV=y
  - linux 6.12 drivers/spi/Kconfig:1228 - the symbol is SPI_SPIDEV; no 'config SPIDEV' exists
- **Kök neden:** Hand-written fragment with no check that each fragment symbol exists in the final .config (merge_config only warns).
- **Mimari düzeltme yönü:** Replace with CONFIG_SPI_SPIDEV=y. Make it detectable: a CI step that fails when any fragment symbol is missing from, or has a different value in, the final .config (parse merge_config warnings or diff the fragment against .config).
- **Doğrulama:** Build-time assertion over output/build/linux-*/.config that every fragment line is honoured. On device: /dev/spidev0.* exists once SPI is enabled in the effective DT.
- **Not:** spidev may still exist as a module from the RPi bcm2711_defconfig (not verifiable here: the RPi tarball is not in dl/). In prod the FIT DTB also drops dtparam=spi=on (see incidental).

<a id="EI-066"></a>

### EI-066 — Two suderra-firstboot.service definitions exist; the overlay inline-shell unit in /etc shadows the packaged Rust one, whose advertised TPM/registration/mark-good behaviour never runs

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-firstboot vs rootfs-overlay suderra-firstboot.service
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `package/suderra-firstboot/suderra-firstboot.mk:31-35`, `package/suderra-firstboot/Config.in:8-15`
- **Kanıt (ayrıntı):**
  - package/suderra-firstboot/suderra-firstboot.mk:31-35 installs /usr/lib/systemd/system/suderra-firstboot.service (ExecStart=/usr/bin/suderra-firstboot, ConditionFirstBoot)
  - board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-firstboot.service (inline shell) takes precedence; package/suderra-firstboot/Config.in:8-15 advertises TPM key, cloud registration and mark-good behaviour that never runs
- **Kök neden:** Placeholder and real implementations coexist under one unit name.
- **Mimari düzeltme yönü:** Keep a single firstboot implementation and unit name, and add a contract test failing on duplicate unit names across /etc and /usr/lib in the final image.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-067"></a>

### EI-067 — grubenv on the unauthenticated ESP lets a disk-level attacker select any validly signed slot, including an older image in the other slot

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** board/suderra/x86_64/grub.cfg
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/x86_64/grub.cfg:12-19`
- **Kanıt (ayrıntı):**
  - board/suderra/x86_64/grub.cfg:12-19 load_env from the ESP grubenv with no integrity check; the slot choice follows ORDER/A_OK/B_OK
- **Kök neden:** Boot selection state is unauthenticated and there is no version-floor check at boot.
- **Mimari düzeltme yönü:** Have the kernel/initramfs refuse to continue when the booted image version is below the TPM-NV floor (combine with the T103 fix).
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-068"></a>

### EI-068 — The verity initramfs copies the entire /lib, /lib64 and /usr/lib (52 MB on the x86 dev target) into every signed boot artifact

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** scripts/production-artifacts.sh verity initramfs
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `scripts/production-artifacts.sh:301-311`
- **Kanıt (ayrıntı):**
  - scripts/production-artifacts.sh:301-311,346 cp -a of all library trees
  - du of output/suderra_qemu_x86_64_defconfig/target/usr/lib = 52M
- **Kök neden:** The dependency closure of the few initramfs binaries is not computed.
- **Mimari düzeltme yönü:** Copy only the ldd closure (or use static busybox/dmsetup) and add a size budget check.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-069"></a>

### EI-069 — The Buildroot agent package builds default features only (no scada-display, opc-ua-server or gpio) from a different pinned commit than the release, while its help text advertises OPC UA and SCADA

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-edge-agent Buildroot recipe
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `package/suderra-edge-agent/suderra-edge-agent.mk:17`, `aquaculture_platform/sens-api-gateway/Cargo.toml:424`, `aquaculture_platform/.github/workflows/edge-agent-release.yml:20`
- **Kanıt (ayrıntı):**
  - Suderra-OS package/suderra-edge-agent/Config.in help: 'Modbus TCP/RTU master, OPC UA server, ...'
  - package/suderra-edge-agent/suderra-edge-agent.mk:17 SUDERRA_EDGE_AGENT_CARGO_BUILD_OPTS = --bin suderra-agent (no --features), so the build gets sens-api-gateway/Cargo.toml:424 default=["health"] only
  - aquaculture_platform/.github/workflows/edge-agent-release.yml:20,240 build with --features scada-display, and the .mk pins a different commit (eefc2ceb...), so the OS image agent and the release agent are different feature tiers
  - Latent: the package cannot be selected at all today (claim T80)
- **Kök neden:** The feature tier is not part of the OS package contract and the two build paths share no feature SSoT.
- **Mimari düzeltme yönü:** Define the per-target feature tier in one file consumed by the release workflow and the .mk, with a CI check that both resolve to the same tier.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-070"></a>

### EI-070 — Suderra OS operator output and docs reference a non-existent unit (suderra-edge-agent.service), a root/suderra login and an agent path (/var/lib/suderra/edge/current) that the code contradicts

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-installer / suderra-firstboot messages and docs/security/field-appliance-hardening.md
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `userspace/suderra-installer/src/cmd/install.rs:352-353`, `userspace/suderra-firstboot/src/main.rs:6`, `userspace/suderra-firstboot/README.md:12`, `userspace/suderra-installer/README.md:107-108`, `package/suderra-edge-agent/suderra-edge-agent.mk:38`, `docs/security/field-appliance-hardening.md:13-22`, `board/suderra/common/users.txt:10-15`
- **Kanıt (ayrıntı):**
  - userspace/suderra-installer/src/cmd/install.rs:352-353 prints `systemctl status suderra-edge-agent` and `journalctl -u suderra-edge-agent -f`; userspace/suderra-firstboot/src/main.rs:6, userspace/suderra-firstboot/README.md:12 and userspace/suderra-installer/README.md:107-108 use the same name
  - The real unit is suderra-agent.service (package/suderra-edge-agent/suderra-edge-agent.mk:38; board/.../suderra-firstboot.service:22)
  - docs/security/field-appliance-hardening.md:13-22 describes a 'root / suderra' login and '/var/lib/suderra/edge/current/suderra-agent', while board/suderra/common/users.txt:10-15 locks root and suderra-edge-install:9 uses CURRENT_LINK=/opt/suderra/edge/current
- **Kök neden:** Messages and docs are not generated from or checked against the unit names and paths the scripts use.
- **Mimari düzeltme yönü:** Generate unit names and paths from one contract constant used by the .mk, installer and docs, and add a doc/image contract test that every referenced unit and path exists.
- **Not:** Incidental finding (merged from 2 raw report(s)); area=os.

<a id="EI-071"></a>

### EI-071 — suderra-ota-mark-good.service is installed but never enabled, and would mark the slot good without the health gate

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-ota suderra-ota-mark-good.service
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `package/suderra-ota/suderra-ota-mark-good.service:9`, `package/suderra-ota/suderra-ota.mk:23-26`, `board/suderra/common/post-build.sh:274-279`, `userspace/suderra-ota/src/main.rs:266-291`
- **Kanıt (ayrıntı):**
  - package/suderra-ota/suderra-ota-mark-good.service:9 ExecStart=/usr/bin/suderra-ota mark-good (no gate)
  - package/suderra-ota/suderra-ota.mk:23-26 install only, no wants link; board/suderra/common/post-build.sh:274-279 preset 'disable *'
  - userspace/suderra-ota/src/main.rs:266-291 mark_good calls rauc mark-good without the health checks
- **Kök neden:** There are two mark-good owners; the second was left as dead code.
- **Mimari düzeltme yönü:** Delete the unit or make it the single owner that invokes the health gate; contract test asserting exactly one enabled mark-good unit.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-072"></a>

### EI-072 — install-manifest-json copies unbounded stdin into the persistent spool

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-provision install-manifest-json
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:52`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/usr/sbin/suderra-provision:52 cat > "${REQUEST_DIR}/manifest.json" with no size limit, while the download path has MAX_DOWNLOAD_BYTES
- **Kök neden:** Input bounds exist on the download path (MAX_DOWNLOAD_BYTES) but not on the stdin path.
- **Mimari düzeltme yönü:** Bound the input (head -c limit, reject if more remains) or use a socket protocol with a size field.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-073"></a>

### EI-073 — system.conf.arm registers the slot hook as a system post-install handler, where RAUC_SLOT_CLASS is absent, making it a silent no-op

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-rauc-config system.conf.arm
- **Köken:** yan bulgu (kod okunurken kaydedildi)
- **Kanıt (dosya:satır):** `package/suderra-rauc-config/system.conf.arm:13-14`, `package/suderra-rauc-config/suderra-rauc-arm-slot-hook.sh:12`, `scripts/create-rauc-bundle.sh:239-244`
- **Kanıt (ayrıntı):**
  - package/suderra-rauc-config/system.conf.arm:13-14 [handlers] post-install=/usr/lib/rauc/suderra-rauc-arm-slot-hook.sh
  - package/suderra-rauc-config/suderra-rauc-arm-slot-hook.sh:12 exits 0 unless RAUC_SLOT_CLASS is set (system handlers get RAUC_SLOT_CLASS_<N> instead)
  - The working path is the bundle hook (scripts/create-rauc-bundle.sh:239-244)
- **Kök neden:** Duplicate wiring: the working path is the bundle hook.
- **Mimari düzeltme yönü:** Remove the [handlers] entry or make it iterate RAUC_TARGET_SLOTS; keep one authoritative hook path with a test.
- **Not:** Incidental finding (merged from 1 raw report(s)); area=os.

<a id="EI-074"></a>

### EI-074 — sysctl hardening omits modules_disabled, ldisc_autoload, unprivileged_userfaultfd, bpf_jit_harden and io_uring_disabled

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** sysctl hardening
- **Köken:** doğrulanan iddia T107 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/sysctl.d/90-suderra-hardening.conf:1-71`, `board/suderra/common/kernel-fragment.config:50`, `board/suderra/x86_64/linux-x86_64.config:201`
- **Kanıt (ayrıntı):**
  - board/suderra/common/rootfs-overlay/etc/sysctl.d/90-suderra-hardening.conf:1-71 - none of kernel.modules_disabled, dev.tty.ldisc_autoload, vm.unprivileged_userfaultfd, net.core.bpf_jit_harden, kernel.io_uring_disabled
  - x86 already has MODULES and USERFAULTFD off at build time (kernel-fragment.config:50, linux-x86_64.config:201); ARM has MODULES=y (T89)
- **Kök neden:** The sysctl list predates the ARM module/io_uring surface review and is not derived from a hardening baseline (e.g. KSPP).
- **Mimari düzeltme yönü:** Add the keys with the '-' prefix where a symbol may be absent. Add kernel.modules_disabled=1 via a late oneshot after module loading on ARM, or remove modules entirely. Better: compile out IO_URING/USERFAULTFD and set BPF_JIT hardening at build time, and check the effective sysctl values against a KSPP-derived baseline in CI.
- **Doğrulama:** QEMU and hardware: sysctl -a assertions in the runtime evidence suite. A kconfig-hardened-check style report on the final .config.

<a id="EI-075"></a>

### EI-075 — post-build strips setuid but not setgid bits, contrary to its whitelist comment

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** post-build hardening
- **Köken:** doğrulanan iddia T109 (CONFIRMED)
- **Kanıt (dosya:satır):** `board/suderra/common/post-build.sh:95-97`
- **Kanıt (ayrıntı):**
  - board/suderra/common/post-build.sh:95-97 - find -perm /4000 ... chmod u-s, errors swallowed (|| true); comment says 'only the whitelist remains' but there is no whitelist and setgid (/2000) is untouched
- **Kök neden:** Ad-hoc hardening step with no explicit allow-list or verification.
- **Mimari düzeltme yönü:** Replace with an allow-list (an empty set is expected): strip u+s and g+s from everything not listed, and fail the build if any setuid/setgid file remains outside the list.
- **Doğrulama:** Image contract test: find target -perm /6000 -type f must be empty or equal to the allow-list.

<a id="EI-076"></a>

### EI-076 — The USB self-installer takes its payload key, verifier, rollback floor, key epoch, target board and confirmation from SUDERRA_INSTALLER_* environment variables

- **Önem:** Orta · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** package/suderra-os-installer suderra-os-install
- **Köken:** bağımsız inceleme (OS track review, 2026-10-20)
- **Kanıt (dosya:satır):** `package/suderra-os-installer/suderra-os-install:4-22`, `package/suderra-os-installer/suderra-os-installer.mk:25-26`, `package/suderra-os-installer/suderra-os-install.service:11`, `tests/installer/suderra-os-install-test.sh:40-43`
- **Kanıt (ayrıntı):**
  - suderra-os-install:9-10 `PUBKEY="${SUDERRA_INSTALLER_PUBKEY:-…}"`, `VERIFY_BIN="${SUDERRA_INSTALLER_VERIFY_BIN:-…}"`: the payload index key and the verifier binary come from the environment
  - suderra-os-install:12-13,15,19-21: `ALLOW_USB_TARGET`, `USB_TARGET_BY_ID`, `ASSUME_YES`, `TARGET_BOARD`, `MIN_KEY_EPOCH`, `MIN_ROLLBACK_FLOOR` likewise
  - suderra-os-installer.mk:25-26 installs the script on every image that selects BR2_PACKAGE_SUDERRA_OS_INSTALLER, every production image included (enabled only on the USB installer image)
  - tests/installer/suderra-os-install-test.sh drives every fixture (sysfs, /dev, device-tree, payload, key, verifier) through these variables
- **Kök neden:** The script's test seam is the environment, so test-fixture paths and security decisions share one override mechanism that a runtime unit drop-in can also reach (ADR-048 DEC-19).
- **Mimari düzeltme yönü:** Fix every security-relevant value (payload key, verifier, epoch, floor, USB-target permission, confirmation, board) as an image fact on the verity root; give tests a fixture root that production code cannot select (move the selection and verification logic into suderra-installer, where `Paths::under` exists only under `cfg(test)`), and remove the script from production images that never run it.
- **Doğrulama:** tests/security/no-security-env-in-prod-test.sh lists this script as tracked (EI-076); removing it from that list must pass once fixed. Installer test runs against a fixture root without any SUDERRA_INSTALLER_* variable.

<a id="EI-077"></a>

### EI-077 — systemd is built without seccomp on every image, so every unit's SystemCallFilter=, RestrictAddressFamilies=, MemoryDenyWriteExecute=, LockPersonality=, RestrictRealtime= and SystemCallArchitectures= are dropped, the agent's included

- **Önem:** Yüksek · **Faz:** P0 · **Son tarih:** 2026-11-02 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** configs/*_defconfig (systemd build), every overlay unit with a seccomp sandbox directive
- **Köken:** QEMU edge e2e test (tests/qemu/edge-readonly-sandbox-test.py), 2026-10-20
- **Kanıt (dosya:satır):** `buildroot/package/systemd/systemd.mk:191-196`, `configs/suderra_qemu_x86_64_defconfig:48`, `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-agent.service` (SystemCallFilter=, RestrictAddressFamilies=, MemoryDenyWriteExecute=, LockPersonality=, RestrictRealtime=, SystemCallArchitectures=)
- **Kanıt (ayrıntı):**
  - the dev QEMU image's systemd reports `systemd 256.17 running in system mode (... -SECCOMP ...)` at boot
  - systemd.mk builds `-Dseccomp=enabled` only with BR2_PACKAGE_LIBSECCOMP=y, which no defconfig selected
  - `systemd-run -p RestrictAddressFamilies=...` on that image fails "Cannot set property RestrictAddressFamilies, or unknown property"; in unit files systemd drops the same directives
  - the agent release requires CONFIG_SECCOMP_FILTER from every image's kernel for exactly this unit sandbox (aquaculture_platform sens-api-gateway/release/edge-release.toml), which the kernel has and systemd never used
- **Kök neden:** The unit sandbox was specified and tested as text (unit-directives.json, edge-agent-unit-contract-test.sh) but never against the systemd the images build.
- **Mimari düzeltme yönü:** Select BR2_PACKAGE_LIBSECCOMP=y in every systemd defconfig; fail the image contract when a systemd defconfig lacks it; check +SECCOMP on the booted image.
- **Doğrulama:** tests/image-contracts/edge-agent-unit-contract-test.sh refuses a systemd defconfig without libseccomp; tests/qemu/edge-provisioning-e2e.py requires +SECCOMP in the booted systemd's feature string and edge-readonly-sandbox-test.py runs the agent and the installer under their units' seccomp directives.

<a id="EI-078"></a>

### EI-078 — No image selects e2fsprogs, so production first-boot /data provisioning dies at mkfs.ext4 after the LUKS volume is already formatted and TPM-sealed, and no image has fsck.ext4

- **Önem:** Kritik · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** Buildroot defconfigs (e2fsprogs, BusyBox applets) and suderra-data-unlock
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-os-no-e2fsprogs-mkfs-ext4)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:155`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:176`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock:179`, `configs/suderra_x86_64_defconfig:88`, `configs/suderra_aarch64_rpi4_prod_ab_defconfig:210`, `configs/suderra_aarch64_revpi4_prod_ab_defconfig:124`, `configs/suderra_qemu_x86_64_prod_ab_defconfig:82`, `buildroot/package/busybox/busybox.config:662`, `tests/image-contracts/data-luks-provision-contract-test.sh:34`
- **Kök neden:** No defconfig selects BR2_PACKAGE_E2FSPROGS (resolved .config of suderra_x86_64, rpi4_prod_ab, revpi4_prod_ab and qemu_x86_64_prod_ab all say '# BR2_PACKAGE_E2FSPROGS is not set'), and BusyBox is built with only the mke2fs applet (CONFIG_MKE2FS=y, MKFS_EXT2 unset), so mkfs.ext4 and fsck.ext4 exist on no image (the built QEMU target has only usr/sbin/mke2fs). suderra-data-unlock runs mkfs.ext4 only on the boot that has just luksFormat-ed and TPM-enrolled the partition (fresh=1 exists only while isLuks fails). Under set -eu the missing command aborts the script with 127 after the volume is sealed. The next boot sees a LUKS header (fresh=0), skips mkfs, and mount_data fails with data-unmountable, so every production device is LOCKED after first boot until reflashed. It is hidden behind EI-020 (x86 prod kernel has no dm-crypt) and EI-029 (ARM prod has no TPM) and surfaces as soon as those are fixed. The image-contract test only greps for the string 'mkfs.ext4 ... mapper_dev', never for the binary. The same cause gives the dev QEMU boot log 'fsck.ext4 not found for /dev/vda2', and means the ext4-on-LUKS /data has no e2fsck after power loss. Verified by resolving the four production defconfigs out of tree and by listing the built QEMU target.
- **Mimari düzeltme yönü:** Tier 1/2: have the package that owns suderra-data-unlock select BR2_PACKAGE_E2FSPROGS and its FSCK option through Config.in, so no defconfig can omit them. Tier 3: add a post-build image-fact gate that extracts every external command invoked by the root scripts (mkfs.ext4, fsck.ext4, cryptsetup, systemd-cryptenroll, ...) and asserts each resolves in the target, for every defconfig. Make provisioning transactional: a failed mkfs must erase the fresh LUKS header (as the TPM-enroll failure path already does) so the next boot re-provisions instead of leaving an unformatted sealed volume. Run the fresh-volume mkfs path in the QEMU prod_ab loopback test.

<a id="EI-079"></a>

### EI-079 — Suderra OS userspace/Cargo.lock pins rustls 0.23.40 (four RUSTSEC TLS advisories) and the unmaintained unsafe-libyaml via serde_yaml, so cargo deny, Trivy and Grype fail on main and the root installer/ota/telemetry TLS clients carry known flaws

- **Önem:** Yüksek · **Faz:** P1 · **Son tarih:** 2026-11-30 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** userspace/Cargo.lock and deny.toml (suderra-installer, suderra-ota, suderra-attestation, suderra-telemetry)
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-os-rustls-advisories-cargo-lock)
- **Kanıt (dosya:satır):** `userspace/Cargo.lock:1286`, `userspace/Cargo.lock:167`, `userspace/deny.toml:30`, `userspace/Cargo.toml:57`, `userspace/Cargo.toml:61`
- **Kök neden:** The lockfile was last refreshed before RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries), -0346 (Debug impls expose TLS secrets), -0348 (Brotli certificate decompression allocates up to 1 GiB before authentication) and -0349 (unauthenticated ServerHello downgrades later connections to classical key exchange) were published; all are fixed in rustls >= 0.23.46. suderra-installer, suderra-ota, suderra-attestation and suderra-telemetry all use reqwest with rustls-tls, and the root installer is the activation/manifest TLS client. serde_yaml (deprecated) pulls unsafe-libyaml (RUSTSEC-2024-0449), for which no safe upgrade exists. The CI run on the P0 branch tip shows 'cargo deny check: advisories FAILED' with exactly these five advisories (deny.toml keeps ignore = [] on purpose), and the Security Scan job fails in Trivy fs (--exit-code 1, CRITICAL,HIGH) and Grype (--fail-on high --only-fixed). The last green Rust Userspace run on main is from 2026-07-11, so the advisory database moved under an unchanged lockfile; nothing refreshes the lockfile on a schedule. The agent side is not affected (monorepo Cargo.lock has rustls 0.23.46, rustls-webpki 0.103.15).
- **Mimari düzeltme yönü:** Run cargo update -p rustls (and rustls-webpki) to >= 0.23.46 and re-run cargo deny. Remove serde_yaml from the workspace (Tier 1) by moving the OS-side config files to a maintained parser such as serde-saphyr or to TOML/JSON, instead of adding an ignore entry. Tier 2: add a scheduled cargo-update/dependabot lane for userspace/Cargo.lock so a published advisory produces a fix PR, and make cargo deny a required check for the release workflow.

<a id="EI-080"></a>

### EI-080 — The OS update manifest and the USB payload index are signed over a re-serialized struct, verified with non-strict Ed25519 verify, and accept unknown fields; the Python signer matches Rust only by dict order

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-ota SignedManifest, suderra-installer UsbPayloadIndex, scripts/create-os-update-manifest.py
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-os-signed-documents-reserialized-nonstrict)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:121`, `userspace/suderra-ota/src/main.rs:578`, `userspace/suderra-ota/src/main.rs:586`, `userspace/suderra-installer/src/usb_payload.rs:47`, `userspace/suderra-installer/src/usb_payload.rs:91`, `userspace/suderra-installer/src/usb_payload.rs:583`, `scripts/create-os-update-manifest.py:54`, `scripts/create-os-update-manifest.py:75`
- **Kök neden:** This is the EI-054 class, left in two documents the contract verifier does not cover. SignedManifest (suderra-ota) and UsbPayloadIndex have no deny_unknown_fields, so unknown fields are dropped before verification and are never signed. Both verify with ed25519-dalek VerifyingKey::verify (the contract path uses verify_strict), and the signed bytes are the re-serialization of the parsed struct (serde_json::to_vec for the OTA manifest, a sorted-key rewrite for the USB index). The OTA manifest signer (create-os-update-manifest.py canonical_bytes = json.dumps of a dict) reproduces the Rust bytes only because the dict's key order and null for release_notes happen to equal the struct's field order and Option serialization; reordering either side breaks every signature silently. The USB index sign path re-serializes through the same struct.
- **Mimari düzeltme yönü:** Tier 1: sign and verify the received bytes (a DSSE-style envelope over the exact payload, as the contract statements do) and add deny_unknown_fields plus verify_strict; if the OS keeps its own document types, move them into the contract with golden cross-language vectors so a Python or TypeScript signer cannot diverge. Add a test that adding an unknown field or reordering keys fails verification.

<a id="EI-081"></a>

### EI-081 — suderra-ota writes its state file with write+rename and no fsync, and the rollback-floor file without a directory fsync, so a power cut during an update can leave empty state or lose the floor

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-ota state and rollback-floor persistence
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-ota-state-writes-not-durable)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:802`, `userspace/suderra-ota/src/main.rs:808`, `userspace/suderra-ota/src/main.rs:810`, `userspace/suderra-ota/src/main.rs:827`, `userspace/suderra-ota/src/main.rs:839`
- **Kök neden:** save_state does fs::write to a .tmp and fs::rename: neither the data nor the parent directory is fsynced, so on ext4 a power loss around install, mark-good or rollback can leave a zero-length or stale state.json. persist_rollback_floor fsyncs the file but not the directory, so the rename may not survive. In production load_state refuses to continue without the monotonic floor, so a corrupted state makes every suderra-ota command (mark-good, rollback, install) fail, which the mark-good unit turns into a failed health gate and slot ping-pong. Power loss during an OTA is the normal field failure on these devices.
- **Mimari düzeltme yönü:** Tier 1: one durable-write helper (temp in the same directory, write, fsync file, rename, fsync directory) used for state, floor and the pre-update record; the userspace installer already has write_atomic for this, so share it from a common crate instead of a second implementation. Add a fault-injection test that truncates the temp file before rename.

<a id="EI-082"></a>

### EI-082 — suderra-ota checks the bundle's digest and size, then lets rauc install re-read the file by path, so a bundle swapped in between (removable media) bypasses the manifest and rollback-floor check

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-ota bundle verification and rauc install
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-ota-bundle-check-then-use)
- **Kanıt (dosya:satır):** `userspace/suderra-ota/src/main.rs:679`, `userspace/suderra-ota/src/main.rs:699`, `userspace/suderra-ota/src/main.rs:220`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-runtime-scenario:85`
- **Kök neden:** verify_bundle hashes the file and compares it with the signed manifest, then install() runs 'rauc install <path>', which opens the path again. RAUC verifies the bundle's own signature, so the swap cannot install an unsigned bundle, but an older validly signed bundle can be substituted after the manifest's version, rollback_floor and min_current_version checks, which RAUC itself does not enforce (EI-031). The bundle path comes from caller-controlled locations such as the payload mount. Same class as EI-061 for the USB installer.
- **Mimari düzeltme yönü:** Tier 1: open the bundle once, verify the digest on that descriptor, and hand RAUC the descriptor (/proc/self/fd/N) or copy it into a root-only directory first and install from the copy; additionally have RAUC compare the bundle's version with the verified manifest (rauc info) before installing.

<a id="EI-083"></a>

### EI-083 — The rpi4 and revpi4 dev genimage data.ext4 has no 'empty = true', so genimage fills the SUDERRA-DATA partition with a copy of the whole target rootfs

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** board/suderra/aarch64-rpi4 and aarch64-revpi4 genimage.cfg (dev data.ext4)
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-arm-dev-data-image-copies-rootfs)
- **Kanıt (dosya:satır):** `board/suderra/aarch64-rpi4/genimage.cfg:47`, `board/suderra/aarch64-revpi4/genimage.cfg:26`, `board/suderra/x86_64/genimage-qemu.cfg:25`, `board/suderra/x86_64/genimage-qemu.cfg:29`
- **Kök neden:** The x86 QEMU config documents the rule ('empty = true is required: without it genimage fills a filesystem image with the whole --rootpath'), but the ARM dev configs declare data.ext4 without it or a mountpoint, so /data on every RPi4 and RevPi dev image starts with a second copy of the rootfs (bin, etc, usr ...) beside the data layout the tmpfiles rules create. It wastes the fixed 512M, can make the build fail when the rootfs grows, and puts a duplicate /etc (including the dev provisioning material) on a partition that is writable and mounted by label.
- **Mimari düzeltme yönü:** Tier 1: add empty = true to both data.ext4 images; Tier 3: a post-image check that fails when the data image contains anything but the layout directories, run for every defconfig.

<a id="EI-084"></a>

### EI-084 — suderra-lockdown reports failures with reasons the lockdown result schema forbids (lifecycle-inconsistent, state-corrupt), so those failure paths record no result

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-lockdown script and the lockdown result contract
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-lockdown-failure-reasons-refused)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:39`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:55`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-lockdown:58`, `userspace/suderra-installer/src/contracts/registry.rs:713`, `contracts/suderra-edge/v1/schemas/result.schema.json:355`
- **Kök neden:** The contract allows only receipt-missing, firewall-load-failed and io-error for a lockdown result (registry.rs:713-717, result.schema.json:355-362). The script calls 'result write --kind lockdown --reason lifecycle-inconsistent' when the lifecycle is not ACTIVE and '--reason state-corrupt' when dropbear is still running or the one-time shadow is still bound, i.e. exactly the failures that leave SSH open after provisioning. 'result write' validates and refuses, so nothing is recorded (the script still exits non-zero because the helper fails, but the technician-visible DEC-27 result is missing). The shell script's reason strings are not checked against the contract.
- **Mimari düzeltme yönü:** Tier 1: take the reason from the result registry instead of string literals: either map these failures to the allowed reasons (io-error/receipt-missing) or extend the contract's lockdown reasons in a reviewed version; Tier 3: a test that greps every 'result write --kind K --reason R' in the overlay scripts and checks (K,R) against registry.rs.

<a id="EI-085"></a>

### EI-085 — The QEMU semantic evidence collector fails on every boot: ProtectSystem=strict leaves /run read-only and the unit declares no RuntimeDirectory

- **Önem:** Orta · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** suderra-qemu-semantic-collector unit and script (QEMU images)
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-qemu-semantic-collector-cannot-write-run)
- **Kanıt (dosya:satır):** `board/suderra/common/rootfs-overlay/etc/systemd/system/suderra-qemu-semantic-collector.service:15`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-qemu-semantic-collector:8`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-qemu-semantic-collector:10`, `board/suderra/common/rootfs-overlay/usr/sbin/suderra-qemu-semantic-collector:115`
- **Kök neden:** The script sets WORK_DIR=/run/suderra-qemu-semantic and does 'mkdir -p ... || true', but the unit runs with ProtectSystem=strict, which mounts everything except /dev, /proc and /sys read-only, and has neither RuntimeDirectory= nor ReadWritePaths=. The mkdir fails silently and the next redirect ': > failed-units.txt' cannot create the file, so the collector (enabled only on QEMU images by post-build.sh) produces no failed-units, network or listener evidence, observed on every e2e boot. The QMP acceptance contract test checks the unit text, not that the collector can run.
- **Mimari düzeltme yönü:** Tier 1: declare RuntimeDirectory=suderra-qemu-semantic (and point WORK_DIR at it) so the sandbox and the path cannot disagree; Tier 3: run the collector in the QEMU e2e and fail the lane when its evidence file is absent.

<a id="EI-086"></a>

### EI-086 — The QEMU dev image sets BR2_PACKAGE_SYSTEMD_RESOLVED=n while /etc/resolv.conf points at ../run/resolv.conf, which nothing writes, so the image cannot resolve names

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** configs/suderra_qemu_x86_64_defconfig (resolver)
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-qemu-dev-no-dns)
- **Kanıt (dosya:satır):** `configs/suderra_qemu_x86_64_defconfig:57`
- **Kök neden:** With systemd-resolved disabled, networkd's UseDNS=true has no consumer and the Buildroot skeleton's resolv.conf symlink targets a file no service creates (the built QEMU target shows etc/resolv.conf -> ../run/resolv.conf). The production defconfigs resolve with BR2_PACKAGE_SYSTEMD_RESOLVED=y, so the QEMU lane tests a different DNS stack than production and any hostname-based endpoint or NTP pool fails there.
- **Mimari düzeltme yönü:** Tier 1: drop the =n override so the QEMU image uses the same resolver as production (resolved is already part of the production images), and add an image-fact check that /etc/resolv.conf resolves to a file some enabled unit creates.

<a id="EI-087"></a>

### EI-087 — OS config and doc hygiene: kernel-hardening.md and ota.md name removed or old symbols, dead BR2 symbols in the QEMU defconfig, an unneeded CONFIG_TCG_VTPM_PROXY in the x86 kernel, and a build-order versus Kconfig inversion for suderra-ota

- **Önem:** Düşük · **Faz:** P2 · **Son tarih:** 2026-12-31 · **Sahip:** @Okan-wqm · **Durum:** OPEN
- **Bileşen:** docs/security/kernel-hardening.md, docs/operations/ota.md, QEMU defconfig, x86 kernel config, suderra-ota package
- **Köken:** yan bulgu (P0 sırasında kaydedildi, I-os-kernel-doc-build-hygiene)
- **Kanıt (dosya:satır):** `docs/security/kernel-hardening.md:56`, `docs/security/kernel-hardening.md:62`, `docs/security/kernel-hardening.md:63`, `docs/security/kernel-hardening.md:68`, `docs/operations/ota.md:64`, `configs/suderra_qemu_x86_64_defconfig:30`, `configs/suderra_qemu_x86_64_defconfig:31`, `board/suderra/x86_64/linux-x86_64.config:188`, `package/suderra-ota/suderra-ota.mk:11`, `package/suderra-rauc-config/Config.in:5`
- **Kök neden:** The kernel-hardening table lists CONFIG_PAGE_TABLE_ISOLATION, CONFIG_RETPOLINE, CONFIG_X86_INTEL_MPX and CONFIG_HARDENED_USERCOPY_FALLBACK, which are renamed or removed in kernel 6.12 (OS3 resolved the kernel configs but not the doc), and ota.md still shows compatible=suderra-os-x86_64 instead of the per-board value. BR2_TOOLCHAIN_BUILDROOT_LOCALE and _USE_SSP do not survive Kconfig (SSP still resolves to strong). linux-x86_64.config enables CONFIG_TCG_VTPM_PROXY, a host-side vTPM proxy an appliance does not need. suderra-ota.mk builds suderra-ota after suderra-rauc-config while Kconfig makes suderra-rauc-config depend on suderra-ota; every defconfig has both so nothing breaks. Buildroot per-package directories also keep stale copies of reverse dependencies after a feature change (the systemd -SECCOMP incident), which affects local incremental builds only.
- **Mimari düzeltme yönü:** Generate the hardening table from the resolved kernel configs (Tier 2) so it cannot name a dead symbol; correct ota.md from boards.json; delete the dead defconfig lines and CONFIG_TCG_VTPM_PROXY; align the .mk dependency with Kconfig; document that release images are built from a clean tree only.
