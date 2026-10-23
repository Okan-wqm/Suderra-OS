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

## Edge contract keys (ADR-048 DEC-3.9)

The same ceremony produces the signing keys of the edge contract: the statements Suderra OS and the edge
agent exchange with the cloud (`contracts/suderra-edge/v1/statements.json` `purposes`; ADR-048 DEC-3). They
are not OS image roles, so `ci/evidence-contract.yml` does not list them: their evidence is the ceremony
transcript and the row each one gets in the inventory table of [key-management.md](key-management.md)
§Edge sözleşmesi anahtar envanteri, which is also the only list of keyids a production image may pin. The dev/CI
keys (`scripts/gen-dev-keys.sh`, `scripts/ci/prepare-ci-keyring.sh`) and the contract's TEST-ONLY keys take no part
and are never recorded. **Status: not executed. The ceremony is an operator action (ADR-048 question 9); until
it has run no production image pins an edge key, and the production release statements cannot be signed.**

### Key classes

| Purpose | Class | Private key | Signs | Device anchor |
|---|---|---|---|---|
| `edge-release` | offline | allowlisted HSM, non-exportable, one object | the release statement of every production agent release, offline per release | OS image pin |
| `fleet-root` | offline | allowlisted HSM, non-exportable, one object | `trust-anchors` bundles; `key-epoch-advance` (P2) | OS image pin |
| `edge-provisioning` | online until the P2 KMS | generated at the ceremony, then a sensor-service secret (`SUDERRA_EDGE_PROVISIONING_SIGNING_KEY`) | provisioning manifests, update statements, activation receipts | OS image pin and bundle |
| `device-lifecycle` | online until the P2 KMS | generated at the ceremony, then the signer's secret (`SUDERRA_EDGE_DEVICE_LIFECYCLE_SIGNING_KEY`) | device lifecycle statements | OS image pin |
| `config-integrity` | online until the P2 KMS | secret `SUDERRA_EDGE_CONFIG_INTEGRITY_SIGNING_KEY` | site config and site network policy | bundle |
| `rbac-manifest` | online until the P2 KMS | secret `SUDERRA_EDGE_RBAC_MANIFEST_SIGNING_KEY` | the RBAC manifest | bundle |
| `command` | online until the P2 KMS | secret `SUDERRA_EDGE_COMMAND_SIGNING_KEY` | command envelopes of the platform actor | bundle |
| `edge-image` | P2 | KMS | the verity root hash of a release image | kernel keyring |

An online key outside a KMS is a tracked, accepted risk for monitoring-only pilots (ADR-048 EDGE-HIGH-119, owner
@Okan-wqm, deadline 2026-12-31): a leaked one can sign false manifests, site configs or commands. `edge-release`
and `fleet-root` stay offline, so a leak of any online key cannot sign a release or a trust anchor.
`mqtt-ca` is no ceremony key in P1 (the production bundle names the public CA roots).

### Procedure

The Ceremony section's preconditions and steps 1, 2, 5 and 6 apply unchanged (ticket with three approvers, token
identity, transcript, witnessed validation, retained evidence). The key generation of step 3 differs by class:

1. **Ticket.** Lists every row of the inventory table to be produced (purpose, epoch, class), the HSM serial, token
   label and connector, and the custodians of the two offline keys.
2. **Offline keys** (`edge-release`, `fleet-root`). One object each, never the same object or password for both,
   generated inside the HSM with the Ed25519 signing capability only and no export capability; the witness reads the
   object's capabilities from the token before the object is used. On a YubiHSM 2 (the approved provider of
   `ci/evidence-contract.yml`), with the action and options of the `yubihsm-shell` manual
   (<https://dokk.org/manpages/debian/13/yubihsm-shell/yubihsm-shell.1.en>; confirm each against `--help` of the
   installed version):
   ```bash
   yubihsm-shell --connector <connector of the ticket> --authkey <auth key id> -a generate-asymmetric-key \
       -i <object id> -l edge-release-1 -d <domain> -c sign-eddsa --algorithm=ed25519
   yubihsm-shell --connector <connector of the ticket> --authkey <auth key id> -a get-object-info \
       -i <object id> -t asymmetric-key
   yubihsm-shell --connector <connector of the ticket> --authkey <auth key id> -a get-public-key \
       -i <object id> --outformat PEM > edge-release-1.pub
   ```
3. **Online keys** (`edge-provisioning`, `device-lifecycle`, `config-integrity`, `rbac-manifest`, `command`). Generated on
   the offline ceremony machine with OpenSSL 3 (`openssl genpkey -algorithm ED25519`). This is the one place where
   an edge private key exists outside an HSM, and the transcript records the exception: it applies to online keys only,
   never to `edge-release` or `fleet-root`. Each private key goes straight into its secret store under the two-person
   rule (the signing operator enters it, the witness confirms it is stored), then the file is shredded and the
   machine's volatile storage wiped before the ceremony closes. The public half is exported.
4. **Public keys.** Every exported file must be an Ed25519 SubjectPublicKeyInfo PEM; the tool of step 5 refuses
   anything else.
5. **Inventory.** For each public key:
   `python3 -I package/suderra-keys/edge_key_inventory.py row --purpose <p> --epoch 1 --public-key <file> --origin <origin>`
   prints the row (the keyid is computed, never typed). The rows replace the `bekliyor: operatör` rows,
   `edge_key_inventory.py check` and `rust` follow, and the `rust` output replaces `PRODUCTION_KEYIDS` in
   `userspace/suderra-installer/src/trust_anchors.rs`, all in one reviewed commit that the witness confirms against
   the transcript. `tests/image-contracts/edge-key-inventory-contract-test.sh` keeps table and constant equal.
6. **Cloud secrets.** The five online private keys become `SUDERRA_EDGE_*_SIGNING_KEY` in the sensor-service secret
   store; the fleet-root public key becomes an `<epoch>:<base64 raw key>` entry of `SUDERRA_EDGE_FLEET_ROOT_KEYS`.
7. **First trust-anchors bundle.** Signed by the offline `fleet-root` key and carried in `SUDERRA_EDGE_TRUST_ANCHORS`.
   No tool does this with an HSM key yet (INFRA-MEDIUM-257, deadline 2026-11-30): until it exists this step is blocked
   and the ceremony is not complete.
8. **Release signing path.** Set up the offline release flow of aquaculture_platform
   `docs/runbooks/edge-release-offline-signing.md`: the repository variable `EDGE_RELEASE_SIGNING_MODE=offline`, the
   environment `edge-release-publish` with `EDGE_RELEASE_KEYID` (the `edge-release` row's keyid), the deleted CI signing
   secret, the tag rules. Rehearse with a throwaway key before the first production tag, then sign the first production
   release statement with the HSM.
9. **Production images.** The trust-root set of a production hardware image carries only the four OS-pinned public keys
   (`edge/<purpose>/<epoch>.pub`); `package/suderra-keys` pins a key only when the table records its keyid for that
   purpose and epoch, and the installer's allowlist refuses any other at run time.

### Checklist

- [ ] Ticket approved by release owner, security owner and signing operator; rows, serial, token and connector recorded
- [ ] Transcript started before the token was unlocked; HSM serial, label and connector confirmed against the ticket
- [ ] `edge-release` and `fleet-root` generated in the HSM, capabilities read back by the witness, no export capability
- [ ] Public keys exported as Ed25519 SubjectPublicKeyInfo PEM and checked by `edge_key_inventory.py row`
- [ ] Five online keys generated, stored in their secrets under the two-person rule, files shredded, machine wiped
- [ ] Inventory rows and `PRODUCTION_KEYIDS` recorded in one commit; `edge-key-inventory-contract-test.sh` green
- [ ] Cloud secrets set; `SUDERRA_EDGE_FLEET_ROOT_KEYS` carries the fleet-root public key
- [ ] First production trust-anchors bundle signed by fleet-root (blocked by INFRA-MEDIUM-257)
- [ ] Offline release flow set up and rehearsed; the CI signing secret deleted; first production release signed
- [ ] Backups of both offline keys under the Backup And Recovery rules; recovery drill date set
- [ ] Transcript signed by both participants; evidence retained under the SSOT policy

### Custody

| Key | Holders | Where | Backup |
|---|---|---|---|
| `edge-release` | signing operator and security witness (two-person) | allowlisted HSM, offline | the Backup And Recovery rules |
| `fleet-root` | signing operator and security witness (two-person) | allowlisted HSM, offline | the Backup And Recovery rules |
| online keys | the secret store's administrators; no one holds a copy | sensor-service and signer secrets | none: a lost key is replaced by a new epoch |

## Rotation and compromise of edge keys

Per-key rotation, revocation and compromise procedures are one section each in aquaculture_platform
`docs/runbooks/edge-key-compromise.md` (ADR-048 DEC-15; a skeleton in P1: the fleet-root-signed `key-epoch-advance`
statement that revokes a key is P2). What a P1 ceremony fixes already: every key has its own epoch directory, an OS
image can pin epochs N and N+1 together (DEC-3.4), a bundle-anchored key is replaced by a new bundle, and a
`fleet-root` compromise is answered with an image that pins a new `fleet-root`, delivered over the separate RAUC
chain. The annual fleet-wide re-keying drill runs on the QEMU fleet.

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
