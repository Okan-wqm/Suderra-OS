# RC Evidence Dry-Run

RC evidence dry-run, release operatorlerinin yeni SSOT evidence mimarisini
yayın yetkisi vermeden prova etmesi içindir. Bu akış production readiness
kanıtı değildir ve `production_ready=false` durumunu değiştirmez.

## Authority

Authoritative policy yalnız şu dosyalardadır:

- `ci/build-matrix.yml`
- `ci/evidence-contract.yml`
- `ci/github-governance-policy.yml`

Bu doküman prosedür tarif eder. Target listesi, schema version, required evidence
path, signing role, runtime scenario veya retention yılı elle yeniden tanımlanmaz.
Bunlar `scripts/evidence/evidence_contract.py` çıktısından alınır.

<!-- suderra-generated: output-trees -->
| Root | Path Template | Schema Role | Required By Default | Promotable | Operator Ingress | Release Tag | Dry-Run Input | Gitignore |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `build-artifacts` | `build-artifacts` | `image_build_artifacts` | `True` | `True` | `False` | `True` | `False` | `False` |
| `release-approvals` | `release-approvals/{version}` | `release_approval` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-dry-run` | `release-dry-run/{version}` | `rc_evidence_dry_run` | `False` | `False` | `False` | `False` | `True` | `True` |
| `release-governance` | `release-governance/{version}` | `governance_snapshot` | `False` | `True` | `True` | `True` | `True` | `True` |
| `release-ingress` | `release-ingress/{version}` | `release_ingress` | `True` | `True` | `False` | `True` | `True` | `True` |
| `release-inputs` | `release-inputs/{version}` | `release_input_binding` | `True` | `True` | `False` | `True` | `True` | `False` |
| `release-lab-input` | `release-lab-input/{version}` | `lab_input` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-ota` | `release-ota/{version}` | `ota_evidence` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-reproducibility` | `release-reproducibility/{version}` | `reproducibility_evidence` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-retention` | `release-retention/{version}` | `retention_evidence` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-runtime` | `release-runtime/{version}` | `production_runtime` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-security` | `release-security/{version}` | `security_evidence` | `False` | `True` | `True` | `True` | `True` | `True` |
| `release-signing` | `release-signing/{version}` | `signing_evidence` | `False` | `True` | `True` | `True` | `False` | `True` |
| `release-subject-graph` | `release-subject-graph/{version}` | `release_subject_graph` | `False` | `True` | `False` | `True` | `True` | `True` |
<!-- /suderra-generated -->

<!-- suderra-generated: profile-gates -->
| Profile | Release Authorizing | Publication Allowed | Operator Ingress Required | Required Output Trees |
| --- | --- | --- | --- | --- |
| `ci` | `False` | `False` | `False` | `none` |
| `dev` | `False` | `False` | `False` | `none` |
| `ga` | `True` | `True` | `True` | `release-subject-graph` |
| `production-candidate` | `True` | `True` | `True` | `release-subject-graph` |
| `rc-evidence-dry-run` | `False` | `False` | `False` | `release-subject-graph`, `release-dry-run` |
| `release-candidate` | `True` | `True` | `True` | `release-subject-graph` |
| `technical-dry-run` | `False` | `False` | `False` | `none` |
<!-- /suderra-generated -->

## Dry-Run Flow

Temiz `origin/main` çalışma ağacı kullanılır. Yerel dirty workflow dosyaları
GitHub Actions tarafından çalıştırılmaz; operator önce source SHA, Image Build
run ID ve run attempt değerlerini kayıt altına alır.

```bash
VERSION=v0.1.0-rc.1
SOURCE_SHA=<main-sha>
SOURCE_RUN_ID=<successful-image-build-run-id>

python3 scripts/evidence/evidence_contract.py validate
python3 scripts/evidence/evidence_contract.py validate-join
python3 scripts/evidence/evidence_contract.py output-tree-plan \
  --version "${VERSION}" \
  --profile rc-evidence-dry-run
```

GitHub tarafında `Release Preflight` şu profille çalıştırılır:

```bash
gh workflow run "Release Preflight" \
  -f version="${VERSION}" \
  -f source_sha="${SOURCE_SHA}" \
  -f source_run_id="${SOURCE_RUN_ID}" \
  -f profile=rc-evidence-dry-run
```

Workflow, Image Build artifact byte setini indirir, `release-inputs`, subject
graph ve canonical `release-dry-run/<version>/bundle-manifest.json` üretir.
`dry-run-report.json` yalnız bu bundle manifest'e işaret eden özet kayıttır.
Dry-run artifact adı profile bağlıdır ve release tag binding tarafından kabul
edilmez.

## Expected Output

Dry-run bundle içinde şu contract-derived alanlar bulunur:

- `plans/validate-join.txt`
- `plans/output-tree-plan.json`
- `plans/subject-plan/*.json`
- `plans/runtime-plan/gaps.json`
- `plans/retention-plan.json`
- `digests/image-build-artifacts.json`
- `bundle-manifest.json`
- `gaps.json`
- `dry-run-report.json`

`bundle-manifest.json` her dry-run üyesini ve dış SSOT referanslarını
`sha256`, byte size ve schema role ile bağlayan tek replay root'tur.
`gaps.json` production için kalan gerçek evidence boşluklarını blocker olarak
taşır. Bu boşluklar fake evidence ile kapatılamaz.

## Promotion Boundary

`rc-evidence-dry-run` profili non-promotable'dır:

- signed release tag için kullanılamaz.
- GitHub Release yayınını tetikleyemez.
- HSM, scanner-native raw, retention restore, hardware acquisition veya TPM
  production kanıtı yerine geçmez.

Gerçek RC yayını için ayrı `release-candidate` preflight gerekir. Bu preflight
yalnız signed operator evidence ingress artifact'i ve exact ingress manifest
digest'i ile geçebilir.

## Tag Binding Cutover

Live release gate için annotated tag içinde `Suderra-Preflight-Profile`
zorunludur. Pre-release tag yalnız `release-candidate`, GA tag yalnız
`production-candidate` profile-bound preflight artifact'i ile yayın yetkisi
alabilir. `rc-evidence-dry-run` artifact adı, run ID'si veya ingress digest'i
tag annotation'a yazılsa bile release authorization sağlamaz.

Eski arşiv tag'lerinde bu alan yoksa davranış yalnız offline/archive verification
bağlamında ele alınır. Legacy metadata, mevcut release gate'i
başlatmak, draft release oluşturmak, asset imzalamak veya promotion yapmak için
kabul edilmez.

## Production Gap Handoff

Dry-run sonrası production boşlukları ayrı PR'larda kapatılır:

- gerçek HSM ceremony ve role-specific crypto replay
- scanner-native raw producer operasyonel kullanımı
- immutable retention archive restore/replay proof
- governed station acquisition ve hardware subject
- OTA/RAUC/TPM monotonic rollback evidence
