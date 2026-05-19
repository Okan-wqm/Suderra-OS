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
| - `Build / Build qemu-x86_64` | ✓ (Faz 1+) | Build çalışır |
| - `Build / Build rpi4` | ✓ | RPi4 image contract |
| - `Build / Build revpi4` | ✓ | RevPi4 image contract |
| - `Build / Build payload image pi-cm4-revpi-usb-installer` | ✓ | USB installer image contract |
| - `Build / Build suderra-installer (x86_64)` | ✓ | Preflight-bound installer binary |
| - `Build / Build suderra-installer (aarch64)` | ✓ | Preflight-bound installer binary |
| - `Build / QEMU boot smoke test (qemu-x86_64)` | ✓ | Boot smoke |
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

`release-publish` environment'ı GitHub Environments altında tanımlanır:

- Required reviewers: release manager ve maintainer/security-compliance rolünden
  iki farklı GitHub kullanıcısı
- Deployment branches/tags: selected refs `refs/tags/v*`
- Governance read token: `GOVERNANCE_READ_TOKEN` branch protection, rulesets,
  environments, deployment branch policies, workflow permissions ve audit
  snapshot okumalıdır
- Release tag trust controls: secret `SUDERRA_RELEASE_TAG_SIGNING_PUBLIC_KEY` ve
  variable `SUDERRA_RELEASE_TAG_SIGNING_FINGERPRINTS` tag signer trust-root'u sağlar
- Cosign ve provenance için long-lived signing secret gerekmez; GitHub OIDC ile
  keyless çalışır

Release workflow iki yetki alanına ayrılmıştır:

- `release-evidence` job'ı staged release bytes, cosign imzaları, GitHub
  attestations, machine verification ve evidence üretir. Bu job `contents: read`,
  `id-token: write` ve `attestations: write` kullanır; release yayınlama yetkisi
  yoktur.
- `publish` job'ı sadece `release-publish` protected environment altında çalışır
  ve tek `contents: write` yetkisine sahip job'dır.

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
