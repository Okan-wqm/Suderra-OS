# Coding Standards

> **Status:** Active.

## Genel İlkeler

- **Açıklık > Akıllılık** — Kod 6 ay sonra okunabilmeli
- **Pinli > Esnek** — Versiyonlar pinli, çevre değişkenlerine güvenilmez
- **Fail fast > Sessiz hata** — Hata = exit non-zero + log
- **Reproducibility > Hız** — Deterministik output

## Shell Scripts

```bash
#!/usr/bin/env bash
set -euo pipefail              # Hata = exit, undefined var = exit, pipe failure = exit
IFS=$'\n\t'                    # Word splitting kontrolü

# 4 space indent
function do_thing() {
    local arg="${1:?usage: do_thing <name>}"   # Required arg
    echo "Hello, ${arg}"
}

do_thing "$@"
```

Kurallar:
- `shellcheck` temiz olmalı
- `set -euo pipefail` zorunlu
- Quoted: `"${var}"`, asla `$var`
- `[[ ]]` (not `[ ]`)
- `$(...)`, asla backtick
- Function adları: snake_case
- Komut substitution sonucu mutlaka kontrol

## Markdown

- Satır uzunluğu: yumuşak (uzun cümleler ok)
- Heading hierarchy: H1 sadece dosya başlığı, sonra H2 → H3
- Code block dil etiketi zorunlu: ` ```bash` değil ` ```` (raw)
- Linkler: relative path tercih
- Tablolar > listeler (mümkünse)
- `markdownlint` temiz

## Buildroot `.mk` Dosyaları

```makefile
################################################################################
#
# suderra-edge-agent
#
################################################################################

SUDERRA_EDGE_AGENT_VERSION = 1.6.0
SUDERRA_EDGE_AGENT_SOURCE = ...
SUDERRA_EDGE_AGENT_LICENSE = Apache-2.0
SUDERRA_EDGE_AGENT_LICENSE_FILES = LICENSE
SUDERRA_EDGE_AGENT_DEPENDENCIES = ...

define SUDERRA_EDGE_AGENT_BUILD_CMDS
    # cargo build...
endef

define SUDERRA_EDGE_AGENT_INSTALL_TARGET_CMDS
    # install -m 0755 ...
endef

$(eval $(generic-package))
```

Kurallar:
- 4 space → tab (Buildroot konvansiyonu, `.editorconfig`'de tanımlı)
- `<PKG>_VERSION`, `<PKG>_LICENSE`, `<PKG>_LICENSE_FILES` zorunlu
- Hash file (`.hash`) zorunlu (supply chain)
- DEPENDENCIES eksiksiz

## Rust (Edge Agent paketleme tarafı)

Suderra Edge Agent kodu ayrı repo'da. Suderra OS sadece **paketleme** yapar.

Paketleme kuralları:
- musl target zorunlu: `--target x86_64-unknown-linux-musl`
- Release profile: LTO + opt-level=3 + strip
- `cargo audit` CI'da temiz olmalı

## Kernel Config

- Her CONFIG aç/kapa kararı yorumla
- `kernel-fragment.config` sadece sertleştirme — donanım/protokol config'leri arch-specific dosyalarda
- `make savedefconfig` ile minimal tut

## Commit Mesajları

Conventional Commits. Detay: [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Dosya İsimleri

- Klasör/dosya: `kebab-case` (örn. `kernel-hardening.md`)
- Bash script: `kebab-case.sh`
- Defconfig: `suderra_<arch>_defconfig`
- ADR: `ADR-NNNN-kebab-case-baslik.md`

## Test Yazma

```bash
#!/usr/bin/env bash
set -euo pipefail

# tests/<category>/<name>.sh
# Exit 0 = pass, non-zero = fail
# Output: TAP format (https://testanything.org/)

echo "1..3"
echo "ok 1 - boot tamamlandı"
echo "ok 2 - edge agent active"
echo "not ok 3 - health endpoint 200"
exit 1
```

## CI Yorumları

PR'da CI yorumları: kısa, anlaşılır, action-item-oriented.
Insan dili Türkçe veya İngilizce, tutarlı.

## Yapılacaklar

- [ ] `.pre-commit-config.yaml` ile lokal lint enforcement
- [ ] Pre-merge CI: shellcheck, markdownlint, gitleaks, cargo-deny
- [ ] Dil tercihi netleşmesi (TR vs EN) — şu an karışık
