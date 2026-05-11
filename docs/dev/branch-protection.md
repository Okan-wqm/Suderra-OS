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
| - `Lint / ShellCheck` | ✓ | Code quality |
| - `Lint / Markdown Lint` | ✓ | Docs quality |
| - `Lint / Secret Scan (gitleaks)` | ✓ | Supply chain |
| - `Lint / YAML Lint` | ✓ | Config quality |
| - `Lint / DCO (Signed-off-by) Check` | ✓ | DCO zorunlu |
| - `Build / Build suderra_qemu_x86_64_defconfig` | ✓ (Faz 1+) | Build çalışır |
| - `Security Scan / Trivy (filesystem)` | ✓ | CVE scan |
| - `Security Scan / Trivy (config / Dockerfile)` | ✓ | Config security |
| - `Security Scan / Gitleaks` | ✓ | Secrets |
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
- https://github.com/apps/dco
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
- [ ] Faz 6: Required deployments (production verify)
- [ ] Yıllık: ruleset audit
