# CI Log and Warning Triage

Buildroot emits warnings from upstream toolchains and packages. Suderra-owned
warnings are defects; unclassified third-party warnings are also defects until
triaged.

## Warning Policy

The policy file is `ci/build-warning-policy.json`.

Required fields:

- `known_upstream.owner`: team responsible for periodic review.
- `known_upstream.expires_at`: UTC expiry that forces re-triage.
- `known_upstream.allowed_fingerprints`: exact warning fingerprints already
  reviewed by the owner.
- `third_party.fail`: must be `true`.

The classifier writes warning evidence JSON for each build log:

```bash
python3 scripts/ci/classify-build-warnings.py \
  --policy ci/build-warning-policy.json \
  --json-output build-logs/<defconfig>.warnings.json \
  build-logs/<defconfig>.log
```

## Triage Rules

- `owned`: must be fixed before merge.
- `third-party`: must be fixed or reclassified before merge.
- `known-upstream`: may pass only when every fingerprint is explicitly listed
  in policy and the policy owner/expiry are valid.
- Expired warning policy blocks CI.

The warning evidence stores every fingerprint. If the unique fingerprint count
changes, attach the new evidence JSON to the review. New fingerprints must be
fixed or added to `allowed_fingerprints` with owner approval and an expiry.

## SARIF Uploads

Security scanners must validate SARIF before upload:

```bash
python3 scripts/ci/validate-sarif.py trivy-fs.sarif
```

Invalid or truncated SARIF is treated as a scanner failure, not as a GitHub
upload problem.
