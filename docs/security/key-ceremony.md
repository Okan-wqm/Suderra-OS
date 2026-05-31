# HSM Key Ceremony

Production signing evidence is governed by `ci/evidence-contract.yml` and uses
`suderra.signing-manifest.v2` plus HSM session evidence.

## Ceremony

1. Open a ceremony ticket with release owner, security owner, and signing
   operator approval.
2. Confirm the HSM serial, token label, PKCS#11 URI, key ID, and certificate
   digest.
3. Generate or rotate keys inside the HSM. Private keys must be non-exportable.
4. Record challenge transcript, challenge signature digest, certificate digest,
   artifact signature digest, and final artifact digest for every signing role.
5. Emit `release-signing/<version>/<target>/signing-manifest.json`.
6. Preserve HSM session evidence and audit transcripts under retention policy.

Production replay must verify more than JSON shape. The retained evidence must
include certificate bytes, challenge request/signature/transcript bytes,
artifact bytes, artifact signature bytes, and the verifier command for each
role so `validate-hsm-signing-evidence.py` can replay certificate/key binding,
challenge signature, artifact signature, transcript digest, and final artifact
digest checks.

## Delegation

Release owner and security owner are governance roles. Actual GitHub users or
teams are bound through
`release-governance/<version>/role-bindings.json`; role names alone are not
evidence.

## Backup And Recovery

HSM backup material must use vendor-supported secure backup. Recovery drills
must prove that restored keys match certificate and challenge replay without
using file-backed private keys or SoftHSM for production evidence.

## Rotation And Revocation

Rotate keys on scheduled lifecycle, operator change, suspected exposure, or HSM
replacement. Revoked keys require:

- release freeze
- affected subject graph inventory
- replacement signing manifest
- governance snapshot
- customer-facing verification note when public artifacts are affected

## Compromise Drill

At least annually, replay a key compromise drill from retained evidence:
identify affected releases, revoke trust anchors, rotate HSM keys, regenerate
role bindings, and validate restore/replay evidence from the immutable store.
