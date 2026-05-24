# Branch Protection Rules

GitHub branch protection ayarları. Phase 0 release governance gate olarak bu
ayarlar yalnızca dokümante edilmez; `ci/github-governance-policy.yml` içinde
makine tarafından doğrulanır ve GitHub API snapshot'ları release evidence bundle
içinde saklanır.

## `main` Branch

| Ayar | Değer | Neden |
|---|---|---|
| Require PR before merging | ✓ | Code review zorunlu |
| Require approvals | 2 | Enterprise release governance |
| Dismiss stale reviews when new commits pushed | ✓ | Review güncel kalsın |
| Require review from CODEOWNERS | ✓ | Alan uzmanı onayı |
| Require status checks before merging | ✓ | CI yeşil zorunlu |
| Required status checks: | | |
| - `Lint / Build Matrix Contract` | ✓ | `ci/build-matrix.yml` source-of-truth korunur |
| - `Lint / GitHub Actions Lint` | ✓ | Workflow syntax/actionlint |
| - `Lint / Image Contract + Installer Tests` | ✓ | İmaj sözleşmeleri + installer smoke |
| - `Lint / ShellCheck` | ✓ | Code quality |
| - `Lint / Markdown Lint` | ✓ | Docs quality |
| - `Lint / Secret Scan (gitleaks)` | ✓ | Supply chain |
| - `Lint / YAML Lint` | ✓ | Config quality |
| - `Lint / DCO (Signed-off-by) Check` | ✓ | DCO zorunlu |
| - `Build / Build matrix contract` | ✓ | Matrix contract geçerli |
| - `Build / Syntax and workflow contracts` | ✓ | Fast CI helper/contract syntax |
| - `Build / Buildroot defconfig parse smoke (qemu-x86_64)` | ✓ | QEMU defconfig parse |
| - `Build / Buildroot defconfig parse smoke (rpi4)` | ✓ | RPi4 defconfig parse |
| - `Build / Buildroot defconfig parse smoke (pi-cm4-revpi-usb-installer)` | ✓ | USB installer defconfig parse |
| - `Build / Buildroot defconfig parse smoke (revpi4)` | ✓ | RevPi4 defconfig parse |
| - `Security Scan / Trivy (filesystem)` | ✓ | CVE scan |
| - `Security Scan / Trivy (config / Dockerfile)` | ✓ | Config security |
| - `Security Scan / Gitleaks (secret scan)` | ✓ | Secrets |
| - `Security Scan / Grype (filesystem)` | ✓ | CVE scan (fixed vulns) |
| - `Security Scan / VEX JSON syntax` | ✓ | VEX doküman syntax |
| - `Hadolint (Dockerfile lint) / Hadolint` | ✓ | Dockerfile lint |
| - `Rust Userspace / Format + Clippy + Test` | ✓ | Rust kalite kapısı |
| - `Rust Userspace / Build (x86_64-unknown-linux-musl)` | ✓ | Release binary target |
| - `Rust Userspace / Build (aarch64-unknown-linux-musl)` | ✓ | Release binary target |
| - `Rust Userspace / Security (audit + deny)` | ✓ | RustSec/license/source policy |
| - `Rust Userspace / MSRV check (Rust 1.86)` | ✓ | Toolchain compatibility |
| Require branches to be up to date | ✓ | Rebase zorunlu |
| Require linear history | ✓ | Clean git log |
| Require signed commits | ✓ | Commit authenticity |
| Require deployments to succeed | (Faz 7+) | Production verify |
| Lock branch | ✗ | Geliştirme aktif |
| Do not allow bypassing | ✓ | Admin even |
| Restrict who can push | (Faz 4+ team) | |
| Allow force pushes | ✗ | History koruma |
| Allow deletions | ✗ | Branch koruma |

## `release/v*.x` Branch'leri

Aynı kurallar + ek:

- Require approval: 2 (release manager + maintainer)
- Hotfix için bypass yok

## Release Environment

`release-sign` ve `release-publish` environment'ları GitHub Environments
altında tanımlanır:

- Required reviewers: release manager ve maintainer/security-compliance rolünden
  iki farklı GitHub kullanıcısı
- GitHub environment required reviewers tek onayla deployment başlatabildiği
  için enterprise RC'de bu liste tek başına iki kişilik onay kanıtı sayılmaz.
  `release-owner` ve `security-owner` kararları custom deployment protection
  rule ile veya iki seri protected environment ile ayrı ayrı doğrulanmalıdır.
- Deployment branches/tags: selected refs `refs/tags/v*`
- Governance read token: `GOVERNANCE_READ_TOKEN` branch protection, rulesets,
  environments, deployment branch policies, workflow permissions ve audit
  snapshot okumalıdır
- Governance audit snapshot, `Release Evidence Ingress` artifact'i içinden
  `release-governance/<version>/audit-log.json` olarak gelmelidir; boş veya
  `not_collected` audit log release'i durdurur. Audit snapshot raw GitHub audit
  export digest'i, lookback window'u, collector identity'si ve replay sonucunu
  içermelidir; sadece self-asserted boolean yeterli değildir.
- Release tag trust controls: secret `SUDERRA_RELEASE_TAG_SIGNING_PUBLIC_KEY` ve
  variable `SUDERRA_RELEASE_TAG_SIGNING_FINGERPRINTS` tag signer trust-root'u sağlar
- Cosign ve provenance için long-lived signing secret gerekmez; GitHub OIDC ile
  keyless çalışır

Release workflow iki yetki alanına ayrılmıştır:

- `release-stage` job'ı staged release bytes üretir. Bu job yalnız
  `contents: read` ve `actions: read` kullanır; OIDC signing veya attestation
  yetkisi yoktur.
- `release-sign` job'ı sadece `release-sign` protected environment altında
  çalışır. Cosign imzaları, GitHub attestations, structured machine
  verification kayıtları ve final evidence burada üretilir. Bu job
  `id-token: write` ve `attestations: write` kullanır; release yayınlama
  yetkisi yoktur.
- `publish` job'ı sadece `release-publish` protected environment altında çalışır
  ve tek `contents: write` yetkisine sahip job'dır.

Full image builds, payload assembly, installer binaries and QEMU boot smoke are
not required branch checks. They are produced by `Image Build` and enforced as
release/nightly/manual evidence by Release Preflight.

`Release Evidence Ingress` de required branch check değildir. Operatör/lab
evidence'ını source checkout dışından immutable artifact'e çevirir; artifact
manifesti `source_sha`, Image Build run/attempt, dosya boyutları ve SHA-256
digestleriyle fail-closed doğrulanır.

Manual `workflow_dispatch` release yoktur. Release workflow yalnızca
`refs/tags/v*` push ile çalışır; branch ref'inden tag artifact'i imzalanmaz.
Enterprise alpha dahil tüm `release-publish` onaylarında iki farklı rol gerekir:
release owner ve maintainer/security-compliance approver. Tek release owner
onayı yalnız local technical dry-run için kabul edilir; GitHub Release yayınına
yetmez.

## Rule sets API (GitHub UI dışında)

GitHub Rulesets ile programatik uygulama:

```bash
gh api repos/Okan-wqm/Suderra-OS/rulesets \
    --method POST \
    --header "Accept: application/vnd.github+json" \
    --input - <<EOF
{
    "name": "main-protection",
    "target": "branch",
    "enforcement": "active",
    "conditions": {
        "ref_name": {"include": ["refs/heads/main"], "exclude": []}
    },
    "rules": [
        {"type": "pull_request", "parameters": {"required_approving_review_count": 2}},
        {"type": "required_signatures"},
        {"type": "non_fast_forward"},
        {"type": "required_linear_history"},
        {"type": "required_status_checks", "parameters": {...}}
    ]
}
EOF
```

## DCO Bot

GitHub App `DCO` (dco-app) etkinleştirilmeli:

- <https://github.com/apps/dco>
- Her PR'da Signed-off-by olmayan commit'leri işaretler
- Lint workflow'undaki DCO check yedek

## Doğrulama

Maintainer her release öncesi ve ayda en az 1 kez:

- Yukarıdaki ayarların aktif olduğunu kontrol etmeli.
- Audit log'a bakmalı (kim ayarları değiştirdi).
- Aşağıdaki API snapshot'larını evidence'a koymalı veya release workflow'daki
  collector ile üretmeli:

```bash
python3 scripts/evidence/collect-governance.py \
  --repo Okan-wqm/Suderra-OS \
  --version <version> \
  --output-root release-governance \
  --repo-root .

python3 scripts/evidence/validate-governance.py \
  --policy ci/github-governance-policy.yml \
  --snapshot-root release-governance/<version> \
  --output release-governance/<version>/governance-policy-validation.json
```

## OpenSSF Scorecard ile İzleme

`.github/workflows/scorecard.yml` her hafta:

- "Branch-Protection" check skoru
- Hedef: ≥7/10

## Yapılacaklar

- [x] Faz 0: Governance policy, collector ve validator release evidence'a bağlandı
- [x] Faz 0: Policy 2 reviewer ve role-aware release/security approver gerektirir
- [ ] Admin bootstrap: canlı repo ruleset/branch protection/environment ayarlarını policy ile eşitle
- [ ] Faz 6: Required deployments (production verify)
- [ ] Yıllık: ruleset audit
