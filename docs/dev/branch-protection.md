# Branch Protection Rules

GitHub branch protection ayarları. Bu doküman maintainer tarafından GitHub UI üzerinden uygulanır.

## `main` Branch

| Ayar | Değer | Neden |
|---|---|---|
| Require PR before merging | ✓ | Code review zorunlu |
| Require approvals | 1 (Faz 4+: 2 for security/kernel) | Quality gate |
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
| - `Build / Build pi-cm4-revpi-usb-installer` | ✓ | USB installer image contract |
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

- Required reviewers: release manager veya maintainer
- Deployment branches/tags: selected refs `refs/tags/v*`
- Secrets: bu workflow için secret gerekmez; cosign ve provenance GitHub OIDC ile çalışır

Release workflow sadece `release` job'ında `contents: write`, `id-token: write` ve
`attestations: write` izni alır. Diğer release işleri repository içeriğini read-only
okur.
Manual `workflow_dispatch` release sadece seçilen workflow ref'i input tag ile aynı
`refs/tags/v*` olduğunda geçer; branch ref'inden tag artifact'i imzalanmaz.

## Rule sets API (GitHub UI dışında)

GitHub Rulesets ile programatik uygulama:

```bash
gh api repos/Okan-wqm/suderra-os/rulesets \
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
        {"type": "pull_request", "parameters": {"required_approving_review_count": 1}},
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

Maintainer ayda en az 1 kez:

- Yukarıdaki ayarların aktif olduğunu kontrol etmeli
- Audit log'a bak (kim ayarları değiştirdi)

## OpenSSF Scorecard ile İzleme

`.github/workflows/scorecard.yml` her hafta:

- "Branch-Protection" check skoru
- Hedef: ≥7/10

## Yapılacaklar

- [ ] Faz 0.5: Yukarıdaki ayarları uygula
- [ ] Faz 4: Required reviewers 1→2 (security/kernel için)
- [ ] Faz 4: `release-publish` protected environment reviewers aktif
- [ ] Faz 6: Required deployments (production verify)
- [ ] Yıllık: ruleset audit
