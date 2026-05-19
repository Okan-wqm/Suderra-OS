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
Package-specific canonicalization is allowed only when it collapses equivalent
upstream diagnostics from different host tools into the same reviewed
fingerprint; it must have a contract test that preserves fail-closed behavior
for unrelated warnings.

Each warning record includes both `fingerprint` and `raw_fingerprint`.
`fingerprint` is the canonical policy key. `raw_fingerprint` preserves the log
artifact shape for audit. For example, fragmented POSIX Yacc locations such as
`.1-7: warning: POSIX Yacc...`, `:51.1-7: warning: POSIX Yacc...`, and
`plural.y:51.1-7: warning: POSIX Yacc...` canonicalize to the same reviewed
policy key without adding the fragmented `.1-7` artifact to the allowlist.

## Release Retention

`build-logs/` is local generated output and is ignored by git. For a release
candidate, the successful `Build` workflow uploads `<defconfig>-build-logs`
artifacts containing the raw `.log` and `.warnings.json` files. Release
preflight downloads only the expected build-log artifacts, records their sizes
and SHA-256 digests in `suderra.release-ingress.v1`, and final release evidence
copies them under each target bundle as `build_evidence`.

Do not commit local `build-logs/` into the repository. If a warning triage
decision is needed for release audit, use the signed release evidence archive
or the preflight artifact, not a workstation copy.

## SARIF Uploads

Security scanners must validate SARIF before upload:

```bash
python3 scripts/ci/validate-sarif.py trivy-fs.sarif
```

Invalid or truncated SARIF is treated as a scanner failure, not as a GitHub
upload problem.
