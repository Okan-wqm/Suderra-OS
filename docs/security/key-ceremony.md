# HSM Key Ceremony

Production signing evidence is governed by `ci/evidence-contract.yml` and uses
`suderra.signing-manifest.v2` plus HSM session evidence
(`suderra.hsm-signing-session.v2`). This document is the operational runbook;
schema versions, retention, and required replay checks are defined only in the
SSOT and must not be re-specified here.

Every procedure below is **two-person integrity**: no single operator can
generate, use, back up, or destroy a production key alone. The two roles are the
**signing operator** (drives the HSM) and the **security witness** (verifies and
counter-signs the transcript). Both are bound to real identities via
`release-governance/<version>/role-bindings.json` (see Delegation).

Only HSMs on the approved provider allowlist may be used for production signing
(`ci/evidence-contract.yml` `signing.replay_requirements.approved_provider_allowlist`,
enforced by `validate-hsm-signing-evidence.py --require-production`). SoftHSM,
software tokens, and file-backed keys are rejected.

## Ceremony

Preconditions:

- A ceremony ticket approved by release owner, security owner, and signing
  operator (three distinct people).
- An allowlisted HSM whose serial, token label, PKCS#11 URI, key ID, and
  certificate digest are recorded in the ticket before any key operation.
- A tamper-evident, append-only transcript (screen + audio recording plus a
  written log) started before the token is unlocked.

Steps:

1. Open the ceremony ticket with release owner, security owner, and signing
   operator approval; both ceremony participants confirm the ticket ID on the
   transcript.
2. Confirm the HSM serial, token label, PKCS#11 URI, key ID, and certificate
   digest against the ticket. Abort if any value differs.
3. Generate or rotate keys inside the HSM. Private keys must be created
   non-exportable; the security witness verifies the non-export attribute
   directly on the token.
4. Record the challenge transcript, challenge signature digest, certificate
   digest, artifact signature digest, and final artifact digest for every
   signing role (`os-update-manifest`, `rauc-bundle`, Secure Boot / UKI, GRUB,
   FIT — as applicable to the target).
5. Emit `release-signing/<version>/<target>/signing-manifest.json` and the HSM
   session evidence. The security witness runs
   `validate-hsm-signing-evidence.py --require-production` on the spot and
   records the pass on the transcript.
6. Both participants sign the transcript; preserve HSM session evidence, audit
   log, and transcript under the SSOT retention policy via operator ingress.

Production replay must verify more than JSON shape. The retained evidence must
include certificate bytes, challenge request/signature/transcript bytes,
artifact bytes, artifact signature bytes, and the verifier command for each
role so `validate-hsm-signing-evidence.py` can replay certificate/key binding,
challenge signature, artifact signature, transcript digest, and final artifact
digest checks, and confirm the token identity is on the approved allowlist.

## Delegation

Release owner, security owner, and signing operator are governance roles. Actual
GitHub users or teams are bound through
`release-governance/<version>/role-bindings.json`; role names alone are not
evidence. Bindings are per release version so a personnel change is a new,
auditable binding rather than a silent substitution.

CI never holds a long-lived production key. When automation must sign, the
ceremony issues a **short-lived delegated credential**:

1. The signing operator provisions a time-boxed PKCS#11 session credential on
   the allowlisted HSM (minutes-to-hours TTL, single release scope).
2. The credential's scope, TTL, and issuing ceremony ID are recorded in the
   role bindings and transcript.
3. The credential is injected into the CI job through the protected
   `production-runtime`/release environment only, never committed, and is
   revoked at ceremony close regardless of job outcome.
4. Any signing evidence produced under a delegated credential names the
   delegation record so replay can tie the signature back to the ceremony.

## Backup And Recovery

HSM backup material must use vendor-supported secure backup (wrapped under the
HSM's own backup key or an M-of-N smartcard set); plaintext or file-backed key
export is prohibited. Backups are stored in two geographically separate,
access-controlled locations under the same two-person rule.

Recovery drills (at least annually, and after any HSM replacement) must prove,
end to end, that:

1. A restored key on a fresh allowlisted token reproduces the recorded
   certificate digest and passes challenge-signature replay.
2. A re-signed artifact reproduces the recorded artifact signature and final
   digest for each role.
3. `validate-hsm-signing-evidence.py --require-production` passes against the
   restored-token evidence, including the allowlist check.

No drill "passes" on JSON inspection alone — the restore is only valid when the
replayed signatures match the originals from the immutable store.

## Rotation And Revocation

Rotate keys on scheduled lifecycle, operator change, suspected exposure, or HSM
replacement. Revoked keys require:

- release freeze
- affected subject graph inventory
- replacement signing manifest
- governance snapshot
- customer-facing verification note when public artifacts are affected

## Compromise Drill

At least annually, and immediately on suspected exposure, replay a key
compromise drill from retained evidence. The drill is time-boxed and its own
transcript is retained:

1. **Detect & freeze** — declare the incident, freeze releases, and snapshot the
   current governance/role bindings.
2. **Scope** — enumerate every release whose subject graph references the
   suspect key (affected-release inventory from the immutable evidence store).
3. **Revoke** — revoke the affected trust anchors (db/KEK/FIT/RAUC/OTA as
   applicable) and record the revocation in the subject graph.
4. **Rotate** — run the Ceremony procedure on a fresh allowlisted HSM to mint
   replacement keys; emit replacement signing manifests for in-support releases.
5. **Re-bind** — regenerate `release-governance/<version>/role-bindings.json` and
   any delegated-credential records.
6. **Validate** — replay restore/rotation evidence from the immutable store with
   `validate-hsm-signing-evidence.py --require-production`; confirm the old key
   no longer validates and the new key does.
7. **Disclose** — issue the customer-facing verification note when public
   artifacts were signed by the compromised key.

The drill is only complete when steps 4–6 produce fresh, replay-verified
evidence — a tabletop walkthrough alone does not satisfy it.
