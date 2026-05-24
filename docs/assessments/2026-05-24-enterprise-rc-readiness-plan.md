# Enterprise RC Readiness Plan - 2026-05-24

## Summary

Six read-only agents reviewed the RC hardening plan against the repository.
The result is fail-closed: do not tag `v0.1.0-rc.1` until Image Build key
transfer, evidence ingress trust policy, governance replay evidence, release
publish proof replay, and Rust parity documentation are closed.

## Required Code Closures

- Image Build must not upload or download installer private keyrings. The base
  job materializes public-only trust roots; payload assembly imports the
  installer private key from protected CI signing material and verifies the
  derived public key against the base manifest.
- Release Evidence Ingress trust policy is repo/org governed. Dispatcher inputs
  provide only bundle URL, expected bundle digest, signature URL, and
  certificate URL; accepted host and signer identity come from repository
  policy variables.
- Operator evidence ingress uses `suderra.operator-evidence-ingress.v2`,
  records actual downloaded bundle/signature/certificate digests, and rejects
  expired manifests.
- Governance audit evidence must be replayable. A self-asserted
  `unapproved_governance_changes: false` value is not enterprise evidence.
- Release publish must re-download the final draft, replay cosign and
  attestation checks, verify public proof assets, and only then undraft.
- Rust `release-core` remains shadow-only until parity fixtures prove it is not
  weaker than Python for operator evidence, tag binding, and release ingress.

## External Closures

- The repository must be under an Organization/Enterprise audit source or have
  a formally accepted manual org/enterprise audit export and replay process.
- Configure branch ruleset, tag ruleset, `release-sign`, `release-publish`,
  governance read token, release tag signing trust, operator bundle signer
  trust, and CI installer payload public/private key material before RC.
- Durable evidence export must retain ingress, preflight, tag binding, release,
  proof, and aborted-RC evidence for the policy retention period.

## Validation

Required local validation before PR merge:

```bash
bash -n scripts/ci/prepare-ci-keyring.sh scripts/ci/validate-trust-roots.sh
python3 -B -m py_compile scripts/evidence/operator-evidence-ingress.py \
  scripts/evidence/validate-governance.py scripts/evidence/release-evidence.py
cd host-tools && cargo fmt --all --check && cargo test --locked --workspace
./scripts/run-tests.sh image-contracts
git diff --check
```

After merge, the old Image Build artifact set is invalid. Run a new protected
`main` Image Build for the new SHA, then proceed through evidence ingress,
release-candidate preflight, signed annotated tag, draft prerelease, verified
undraft, and stable promotion.
