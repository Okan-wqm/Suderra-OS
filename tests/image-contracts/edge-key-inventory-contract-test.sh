#!/usr/bin/env bash
#
# The edge key inventory of docs/security/key-management.md (ADR-048 DEC-3.9,
# DEC-3.11, DEC-15) is the one record of the production keyids, and the key
# ceremony fills it. This test holds the table and its consumers together:
#
#   * the table passes every rule of package/suderra-keys/edge_key_inventory.py
#     (a row per purpose of the contract, a unique keyid per key, an origin the
#     purpose allows, the anchor the contract states, no TEST-ONLY key);
#   * the installer's PRODUCTION_KEYIDS is the table rendered as Rust, so a
#     recorded key cannot be forgotten in the source, nor a source key be
#     missing from the table;
#   * the ceremony's helper (`row`) computes the keyid from the exported public
#     key (a dry run with a throwaway key), and refuses what no ceremony may
#     record;
#   * every rule has a case that breaks it and a message that names it.
#
# The production keys themselves, and the ceremony that makes them, are operator
# actions (ADR-048 question 9): until it has run, every row is
# `bekliyor: operatör` and PRODUCTION_KEYIDS is empty.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

if ! command -v openssl >/dev/null 2>&1; then
    echo "SKIP: openssl is not installed (the dry run of the ceremony's helper needs it)" >&2
    exit 77
fi

TOOL="${ROOT}/package/suderra-keys/edge_key_inventory.py"
INVENTORY="${ROOT}/docs/security/key-management.md"
SOURCE="${ROOT}/userspace/suderra-installer/src/trust_anchors.rs"
KEYRING="${ROOT}/contracts/suderra-edge/v1/test-keys/keyring.json"
inventory() { python3 -I "${TOOL}" "$@"; }

expect_fail() {
    local label="$1" pattern="$2"
    shift 2
    local out
    if out="$("$@" 2>&1)"; then
        echo "${label}: accepted" >&2
        exit 1
    fi
    grep -q -- "${pattern}" <<<"${out}" || {
        printf '%s: rejected for the wrong reason (wanted %s):\n%s\n' "${label}" "${pattern}" "${out}" >&2
        exit 1
    }
}

# --- The repository's own table and constant ---------------------------------
inventory check >/dev/null
inventory rust-check >/dev/null
# Until a ceremony has run nothing is recorded, and the source holds no key.
if ! grep -q 'bekliyor: operatör' "${INVENTORY}"; then
    inventory rust | grep -q 'Purpose::' || {
        echo "every row is recorded, but PRODUCTION_KEYIDS renders empty" >&2
        exit 1
    }
fi

# A copy of the table with one line changed: edit <sed-expression> <out>.
edit() {
    local expression="$1" out="$2"
    sed -E "${expression}" "${INVENTORY}" >"${out}"
    ! cmp -s "${INVENTORY}" "${out}" || {
        echo "the edit ${expression} changed nothing: the table moved" >&2
        exit 1
    }
}
check_fails() {
    local label="$1" pattern="$2" file="$3"
    expect_fail "${label}" "${pattern}" python3 -I "${TOOL}" check --inventory "${file}"
}

# --- Every rule of the table has a case that breaks it -----------------------
sed -E 's/^## Edge sözleşmesi anahtar envanteri.*$/## Another heading/' "${INVENTORY}" >"${TMPDIR}/no-heading.md"
check_fails "a table without its heading" "no heading" "${TMPDIR}/no-heading.md"

edit 's/^\| Amaç \| Epoch \| Keyid \| Köken \| Saklama \| Çapa \|$/| Amaç | Epoch | Keyid |/' "${TMPDIR}/header.md"
check_fails "a table with another header" "table header is" "${TMPDIR}/header.md"

edit 's/^\| command \| 1 \|/| teleport | 1 |/' "${TMPDIR}/purpose.md"
check_fails "a purpose that is not an edge key" "is not an edge key purpose" "${TMPDIR}/purpose.md"

edit 's/^\| command \| 1 \|/| command | one |/' "${TMPDIR}/epoch.md"
check_fails "an epoch that is no integer" "epoch is not a positive integer" "${TMPDIR}/epoch.md"

edit 's/^\| edge-release \| 1 \| bekliyor: operatör \| ceremony-hsm-offline \|/| edge-release | 1 | bekliyor: operatör | ceremony-service-secret |/' "${TMPDIR}/origin-offline.md"
check_fails "an offline purpose held as a service secret" "origin 'ceremony-service-secret' is not one of" "${TMPDIR}/origin-offline.md"

edit 's/^\| fleet-root \| 1 \| bekliyor: operatör \| ceremony-hsm-offline \|/| fleet-root | 1 | bekliyor: operatör | kms |/' "${TMPDIR}/origin-kms.md"
check_fails "fleet-root held in a KMS" "origin 'kms' is not one of" "${TMPDIR}/origin-kms.md"

edit 's/^(\| edge-release \| 1 \|.*\| )os-image \|$/\1trust-anchors |/' "${TMPDIR}/anchor.md"
check_fails "an anchor the contract does not state" "the contract says 'os-image'" "${TMPDIR}/anchor.md"

edit 's/^\| rbac-manifest \| 1 \| bekliyor: operatör \|/| rbac-manifest | 1 | ABCDEF |/' "${TMPDIR}/keyid.md"
check_fails "a keyid that is no SHA-256" "neither 'bekliyor: operatör' nor a lowercase hex SHA-256" "${TMPDIR}/keyid.md"

grep -v '^| command | 1 |' "${INVENTORY}" >"${TMPDIR}/no-command.md"
check_fails "a table without a row for a purpose" "no row for \['command'\]" "${TMPDIR}/no-command.md"

grep '^| command | 1 |' "${INVENTORY}" >"${TMPDIR}/twice-row"
python3 -I - "${INVENTORY}" "${TMPDIR}/twice-row" "${TMPDIR}/twice.md" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
extra = open(sys.argv[2], encoding="utf-8").read().rstrip("\n")
at = next(i for i, line in enumerate(lines) if line.startswith("| command | 1 |"))
lines.insert(at + 1, extra)
open(sys.argv[3], "w", encoding="utf-8").write("\n".join(lines))
PY
check_fails "an epoch recorded twice" "recorded twice" "${TMPDIR}/twice.md"

edit 's/^\| edge-image \| 1 \| bekliyor: operatör \|/| edge-image | 1 | '"$(printf '%064d' 1)"' |/' "${TMPDIR}/edge-image.md"
check_fails "a keyid for the P2 edge-image key" "edge-image is a P2 key" "${TMPDIR}/edge-image.md"

# One keyid on two purposes, and the contract's TEST-ONLY keyid, are recorded as
# a ceremony would record any key: in place of `bekliyor: operatör`.
SHARED="$(printf '%064d' 7)"
edit 's/^\| edge-provisioning \| 1 \| bekliyor: operatör \|/| edge-provisioning | 1 | '"${SHARED}"' |/;
      s/^\| device-lifecycle \| 1 \| bekliyor: operatör \|/| device-lifecycle | 1 | '"${SHARED}"' |/' "${TMPDIR}/shared.md"
check_fails "one key serving two purposes" "every purpose has its own key" "${TMPDIR}/shared.md"

TEST_KEYID="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["keys"][0]["keyid"])' "${KEYRING}")"
edit 's/^\| edge-release \| 1 \| bekliyor: operatör \|/| edge-release | 1 | '"${TEST_KEYID}"' |/' "${TMPDIR}/test-only.md"
check_fails "a TEST-ONLY contract key recorded as a production key" "is a TEST-ONLY contract key" "${TMPDIR}/test-only.md"

# --- PRODUCTION_KEYIDS is the table ------------------------------------------
RECORDED="$(printf '%064x' 4660)"
edit 's/^\| edge-release \| 1 \| bekliyor: operatör \|/| edge-release | 1 | '"${RECORDED}"' |/' "${TMPDIR}/recorded.md"
python3 -I "${TOOL}" check --inventory "${TMPDIR}/recorded.md" >/dev/null
expect_fail "a recorded key the source does not carry" "but the inventory records" \
    python3 -I "${TOOL}" rust-check --inventory "${TMPDIR}/recorded.md"
python3 -I "${TOOL}" rust --inventory "${TMPDIR}/recorded.md" | grep -q "Purpose::EdgeRelease, 1, \"${RECORDED}\"" || {
    echo "the rendered constant does not carry the recorded key" >&2
    exit 1
}
# The source after the ceremony: the constant replaced by the rendering (rustfmt's
# layout differs in whitespace only, which the comparison ignores).
python3 -I - "${SOURCE}" "${TMPDIR}/recorded-source.rs" "$(python3 -I "${TOOL}" rust --inventory "${TMPDIR}/recorded.md")" <<'PY'
import re, sys
source = open(sys.argv[1], encoding="utf-8").read()
const = "pub(crate) const PRODUCTION_KEYIDS: &[(Purpose, u16, &str)] = "
start = source.index(const)
end = source.index(";", start) + 1
open(sys.argv[2], "w", encoding="utf-8").write(source[:start] + sys.argv[3].rstrip("\n") + source[end:])
PY
python3 -I "${TOOL}" rust-check --inventory "${TMPDIR}/recorded.md" --source "${TMPDIR}/recorded-source.rs" >/dev/null
# A key in the source that the table never recorded.
expect_fail "a source key the table does not record" "but the inventory records" \
    python3 -I "${TOOL}" rust-check --inventory "${INVENTORY}" --source "${TMPDIR}/recorded-source.rs"
sed -E 's/"[0-9a-f]{64}"/"'"$(printf '%064d' 9)"'"/' "${TMPDIR}/recorded-source.rs" >"${TMPDIR}/other-key-source.rs"
expect_fail "a source key that is not the recorded one" "but the inventory records" \
    python3 -I "${TOOL}" rust-check --inventory "${TMPDIR}/recorded.md" --source "${TMPDIR}/other-key-source.rs"
# The constant is the installer's own declaration: a source without it is refused.
sed -E 's/PRODUCTION_KEYIDS/OTHER_KEYIDS/' "${SOURCE}" >"${TMPDIR}/no-const.rs"
expect_fail "a source without PRODUCTION_KEYIDS" "no pub(crate) const PRODUCTION_KEYIDS" \
    python3 -I "${TOOL}" rust-check --source "${TMPDIR}/no-const.rs"

# --- The ceremony's helper, dry run with a throwaway key ---------------------
KEY="${TMPDIR}/throwaway.key"
PUB="${TMPDIR}/throwaway.pub"
openssl genpkey -algorithm ED25519 -out "${KEY}" 2>/dev/null
openssl pkey -in "${KEY}" -pubout -out "${PUB}" 2>/dev/null
WANT="$(openssl pkey -pubin -in "${PUB}" -outform DER | tail -c 32 | sha256sum | cut -d' ' -f1)"
ROW="$(inventory row --purpose edge-release --epoch 1 --public-key "${PUB}" --origin ceremony-hsm-offline)"
[ "${ROW}" = "| edge-release | 1 | ${WANT} | ceremony-hsm-offline | Offline HSM, iki emanetçi; üretim release statement'ı offline imzalanır | os-image |" ] || {
    printf 'the row of the dry run is not the computed one:\n%s\n' "${ROW}" >&2
    exit 1
}
# The row replaces the pending one and the table, the constant and the checks agree.
python3 -I - "${INVENTORY}" "${ROW}" "${TMPDIR}/dry-run.md" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
at = next(i for i, line in enumerate(lines) if line.startswith("| edge-release | 1 |"))
lines[at] = sys.argv[2]
open(sys.argv[3], "w", encoding="utf-8").write("\n".join(lines))
PY
python3 -I "${TOOL}" check --inventory "${TMPDIR}/dry-run.md" >/dev/null
python3 -I "${TOOL}" rust --inventory "${TMPDIR}/dry-run.md" | grep -q "\"${WANT}\"" || {
    echo "the constant of the dry run does not carry the computed keyid" >&2
    exit 1
}

expect_fail "a ceremony recording an RSA key" "not an Ed25519 SubjectPublicKeyInfo" \
    bash -c "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkey -pubout -out '${TMPDIR}/rsa.pub' 2>/dev/null; python3 -I '${TOOL}' row --purpose edge-release --epoch 1 --public-key '${TMPDIR}/rsa.pub' --origin ceremony-hsm-offline"
expect_fail "a ceremony recording a key as the wrong origin" "origin 'ceremony-service-secret' is not one of" \
    python3 -I "${TOOL}" row --purpose edge-release --epoch 1 --public-key "${PUB}" --origin ceremony-service-secret
expect_fail "a ceremony recording a purpose that is no Ed25519 key" "is not an Ed25519 edge key purpose" \
    python3 -I "${TOOL}" row --purpose edge-image --epoch 1 --public-key "${PUB}" --origin kms
printf 'not a key\n' >"${TMPDIR}/garbage.pub"
expect_fail "a ceremony recording a file that is no key" "not a PEM PUBLIC KEY block" \
    python3 -I "${TOOL}" row --purpose edge-release --epoch 1 --public-key "${TMPDIR}/garbage.pub" --origin ceremony-hsm-offline
# The contract's TEST-ONLY public key, as a ceremony export would look.
python3 -I - "${KEYRING}" "${TMPDIR}/test-only.pub" <<'PY'
import base64, json, sys
entry = json.load(open(sys.argv[1], encoding="utf-8"))["keys"][0]
der = bytes.fromhex("302a300506032b6570032100") + base64.b64decode(entry["public_key"])
body = base64.b64encode(der).decode()
open(sys.argv[2], "w", encoding="ascii").write(
    f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"
)
PY
expect_fail "a ceremony recording a TEST-ONLY key" "is a TEST-ONLY contract key" \
    python3 -I "${TOOL}" row --purpose edge-release --epoch 1 --public-key "${TMPDIR}/test-only.pub" --origin ceremony-hsm-offline

echo "edge key inventory contract passed"
