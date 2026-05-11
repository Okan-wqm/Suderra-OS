# Kernel Sertleştirme — Suderra OS

> **Status:** Skeleton. Tam CONFIG matrisi `board/suderra/common/kernel-fragment.config` ile birlikte Faz 3'te dolacak.

## Felsefe

Suderra OS sadece **bilinen** bir uygulamayı host eder. Bu yüzden uyumluluk için açık tutulan kernel özelliklerinin çoğunu KAPATABİLİRİZ. Her kapama bir attack vector eksilir.

## Sertleştirme Kategorileri

### 1. Boot ve Lockdown

| CONFIG | Değer | Neden |
|---|---|---|
| `CONFIG_SECURITY_LOCKDOWN_LSM` | `y` | Runtime kernel manipülasyonunu kısıtla |
| `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` | `y` | Erken aktive |
| `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` | `y` | En sıkı seviye |
| `CONFIG_INTEGRITY` | `y` | Integrity ölçüm framework |
| `CONFIG_INTEGRITY_SIGNATURE` | `y` | İmza doğrulama |
| `CONFIG_INTEGRITY_TRUSTED_KEYRING` | `y` | Suderra anahtarları |

### 2. Memory Protection

| CONFIG | Değer | Neden |
|---|---|---|
| `CONFIG_RANDOMIZE_BASE` | `y` | KASLR — kernel adres randomization |
| `CONFIG_RANDOMIZE_MEMORY` | `y` | Memory layout randomization |
| `CONFIG_VMAP_STACK` | `y` | Stack guard pages |
| `CONFIG_THREAD_INFO_IN_TASK` | `y` | Stack overflow korumasını güçlendir |
| `CONFIG_PAGE_POISONING` | `y` | Free'lenmiş sayfaları zehirle |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | `y` | Yeni allocation'lar sıfırla |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | `y` | Free'lenmişler sıfırla |
| `CONFIG_STACKPROTECTOR_STRONG` | `y` | Stack canary |
| `CONFIG_FORTIFY_SOURCE` | `y` | strcpy/memcpy bounds check |
| `CONFIG_HARDENED_USERCOPY` | `y` | User-kernel copy bounds |
| `CONFIG_HARDENED_USERCOPY_FALLBACK` | `n` | Strict mode |

### 3. CPU-level Mitigations

| CONFIG | Değer | Neden |
|---|---|---|
| `CONFIG_PAGE_TABLE_ISOLATION` | `y` | KPTI (Meltdown) |
| `CONFIG_RETPOLINE` | `y` | Spectre v2 |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET` | `y` | Kernel stack randomization |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT` | `y` | Default aktif |
| `CONFIG_X86_SMAP` | `y` | (x86) Supervisor Mode Access Prevention |
| `CONFIG_X86_INTEL_UMIP` | `y` | (x86) User Mode Instruction Prevention |
| `CONFIG_X86_INTEL_MPX` | dependent | (x86) Memory Protection Extensions |

### 4. Attack Surface Reduction

| CONFIG | Değer | Neden |
|---|---|---|
| `CONFIG_MODULES` | **n** | Monolithic kernel — modül yüklenmez |
| `CONFIG_MODULE_UNLOAD` | **n** | Modüller olmadığı için |
| `CONFIG_KEXEC` | **n** | Çekirdek değiştirme yasak |
| `CONFIG_KEXEC_FILE` | **n** | Aynı |
| `CONFIG_HIBERNATION` | **n** | Image dump saldırı vektörü |
| `CONFIG_USER_NS` | **n** | Unprivileged user namespace (saldırı yüzeyi) — Edge Agent kullanmıyor |
| `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | `y` | Unprivileged eBPF kapat |
| `CONFIG_BPF_JIT_ALWAYS_ON` | `y` | BPF güvenlik |
| `CONFIG_BPF_LSM` | `y` | (opsiyonel) eBPF LSM |
| `CONFIG_IO_URING` | dependent | Edge Agent tokio kullanıyor — io_uring opsiyonel |
| `CONFIG_LEGACY_VSYSCALL_NONE` | `y` | Vsyscall page yok |
| `CONFIG_COMPAT_VDSO` | **n** | Eski VDSO yok |
| `CONFIG_X86_VSYSCALL_EMULATION` | **n** | (x86) |

### 5. Syscall ve Capability

| CONFIG | Değer | Neden |
|---|---|---|
| `CONFIG_SECCOMP` | `y` | seccomp-bpf desteği |
| `CONFIG_SECCOMP_FILTER` | `y` | BPF filtreler |
| `CONFIG_SECURITY` | `y` | LSM framework |
| `CONFIG_SECURITY_YAMA` | `y` | ptrace_scope vb. |
| `CONFIG_SECURITY_SELINUX` | dependent | (opsiyonel) MAC |
| `CONFIG_SECURITY_APPARMOR` | dependent | (opsiyonel) MAC |
| `CONFIG_DEFAULT_SECURITY` | "yama" veya başka | Default LSM |

### 6. Information Leak Prevention

| sysctl / CONFIG | Değer | Neden |
|---|---|---|
| `kernel.dmesg_restrict` | `1` | dmesg root-only |
| `kernel.kptr_restrict` | `2` | /proc/kallsyms gizli |
| `kernel.unprivileged_bpf_disabled` | `1` | BPF kısıt |
| `kernel.kexec_load_disabled` | `1` | (compile-time'da da kapalı ama runtime ekstra) |
| `kernel.yama.ptrace_scope` | `3` | ptrace tamamen yasak |
| `kernel.perf_event_paranoid` | `3` | perf yasak |
| `fs.protected_hardlinks` | `1` | Symlink saldırıları |
| `fs.protected_symlinks` | `1` | Aynı |
| `fs.protected_fifos` | `2` | FIFO sızma |
| `fs.protected_regular` | `2` | Regular file korumaları |
| `fs.suid_dumpable` | `0` | suid binary core dump yok |
| `kernel.core_pattern` | `\|/bin/false` | Core dump'ı yut |

### 7. Network Sertleştirme

| sysctl | Değer | Neden |
|---|---|---|
| `net.ipv4.conf.all.rp_filter` | `1` | Reverse path filter |
| `net.ipv4.conf.all.accept_source_route` | `0` | Source routing kapat |
| `net.ipv4.conf.all.send_redirects` | `0` | ICMP redirect kapat |
| `net.ipv4.conf.all.accept_redirects` | `0` | ICMP redirect kabul etme |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Smurf koruması |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood |
| `net.ipv6.conf.all.disable_ipv6` | `1` | IPv6 ihtiyaç yoksa kapat |

## Yapılacaklar (Faz 3)

- [ ] `board/suderra/common/kernel-fragment.config` dosyasını tam doldur
- [ ] `board/suderra/common/rootfs-overlay/etc/sysctl.d/90-suderra-hardening.conf` yaz
- [ ] `board/suderra/common/rootfs-overlay/etc/security/limits.d/90-suderra.conf` (ulimit)
- [ ] Lynis baseline tarama → `tests/security/lynis-baseline.sh`
- [ ] KSPP (Kernel Self Protection Project) checklist'i karşılaştır
- [ ] Defektif config kombinasyonları için pen test (KASLR kapalı tutmak vb.)

## Yapamayacaklarımız (kabul edilen riskler)

- **Container runtime yok** → user namespace zaten gerekmez
- **Kernel modülleri yok** → bazı hardware'ler için sürücü desteği kaybolabilir (her hardware için defconfig'te derlenmeli)
- **eBPF kısıtlı** → modern observability araçları sınırlı

## Referanslar

- [Kernel Self Protection Project (KSPP)](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings)
- [CIS Benchmark — Linux Kernel](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [Lynis](https://cisofy.com/lynis/)
- [GrapheneOS hardening](https://grapheneos.org/features) (mobil ama kavramsal olarak benzer)
- ADR-0005: Secure Boot + dm-verity bütünlük katmanı
