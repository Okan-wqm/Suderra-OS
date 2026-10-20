#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

KEYS_DIR="${TMPDIR}/keys"

"${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
"${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${KEYS_DIR}" --expected-profile ci --require-installer-signing

for required in \
    suderra-keys.profile \
    rauc-signing.crt \
    verity-signing.crt \
    installer-payload.key \
    installer-payload.ed25519.pub \
    os-update-manifest.key \
    os-update-manifest.ed25519.pub \
    edge/trust-anchors.dsse.json \
    edge/mqtt-ca/ca.crt; do
    test -s "${KEYS_DIR}/${required}"
done
# One Ed25519 key per purpose, epoch 1 (ADR-048 DEC-3.3, DEC-3.9).
for purpose in edge-release edge-provisioning fleet-root device-lifecycle \
    config-integrity rbac-manifest command; do
    test -s "${KEYS_DIR}/edge/${purpose}/1.pub"
    test "$(stat -c '%a' "${KEYS_DIR}/edge/${purpose}/1.key")" = "600"
done
test ! -e "${KEYS_DIR}/edge-artifact.ed25519.pub"

grep -qx 'ci' "${KEYS_DIR}/suderra-keys.profile"
openssl x509 -in "${KEYS_DIR}/rauc-signing.crt" -noout -subject | grep -q 'Suderra CI RAUC'
openssl x509 -in "${KEYS_DIR}/verity-signing.crt" -noout -subject | grep -q 'Suderra CI Verity'
test "$(stat -c '%a' "${KEYS_DIR}/installer-payload.key")" = "600"
test "$(stat -c '%a' "${KEYS_DIR}/os-update-manifest.key")" = "600"
grep -Eq '^[0-9a-f]{64}$' "${KEYS_DIR}/os-update-manifest.ed25519.pub"

if "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${TMPDIR}/prod" prod >/dev/null 2>&1; then
    echo "prepare-ci-keyring.sh unexpectedly generated prod keys" >&2
    exit 1
fi

PUBLIC_PRIVATE_DIR="${TMPDIR}/public-private"
PUBLIC_ONLY_DIR="${TMPDIR}/public-only"
PRIVATE_ONLY_DIR="${TMPDIR}/private-required"
MISMATCH_DIR="${TMPDIR}/mismatch"
mkdir -p "${PUBLIC_PRIVATE_DIR}"
openssl genpkey -algorithm ED25519 -out "${PUBLIC_PRIVATE_DIR}/installer-payload.key" >/dev/null 2>&1
openssl pkey -in "${PUBLIC_PRIVATE_DIR}/installer-payload.key" -pubout \
    -out "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" >/dev/null 2>&1
PUBLIC_B64="$(base64 -w0 "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub")"
PRIVATE_B64="$(base64 -w0 "${PUBLIC_PRIVATE_DIR}/installer-payload.key")"

SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${PUBLIC_ONLY_DIR}" ci --installer-public-only >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${PUBLIC_ONLY_DIR}" --expected-profile ci --forbid-installer-signing
test -s "${PUBLIC_ONLY_DIR}/installer-payload.ed25519.pub"
test -s "${PUBLIC_ONLY_DIR}/os-update-manifest.ed25519.pub"
if find "${PUBLIC_ONLY_DIR}" -maxdepth 1 -type f -name '*.key' | grep -q .; then
    echo "prepare-ci-keyring.sh public-only mode wrote private key material" >&2
    exit 1
fi
cmp -s "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" "${PUBLIC_ONLY_DIR}/installer-payload.ed25519.pub"

SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64="${PRIVATE_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${PRIVATE_ONLY_DIR}" ci --installer-private-required >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${PRIVATE_ONLY_DIR}" --expected-profile ci --require-installer-signing
cmp -s "${PUBLIC_PRIVATE_DIR}/installer-payload.ed25519.pub" "${PRIVATE_ONLY_DIR}/installer-payload.ed25519.pub"
grep -Eq '^[0-9a-f]{64}$' "${PRIVATE_ONLY_DIR}/os-update-manifest.ed25519.pub"

openssl genpkey -algorithm ED25519 -out "${TMPDIR}/wrong-installer-payload.key" >/dev/null 2>&1
WRONG_PRIVATE_B64="$(base64 -w0 "${TMPDIR}/wrong-installer-payload.key")"
if SUDERRA_CI_INSTALLER_PAYLOAD_PUBLIC_KEY_B64="${PUBLIC_B64}" \
    SUDERRA_CI_INSTALLER_PAYLOAD_PRIVATE_KEY_B64="${WRONG_PRIVATE_B64}" \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${MISMATCH_DIR}" ci --installer-private-required \
        >/dev/null 2>"${TMPDIR}/mismatch.err"; then
    echo "prepare-ci-keyring.sh accepted mismatched installer payload keys" >&2
    exit 1
fi
grep -q 'does not match private signing key' "${TMPDIR}/mismatch.err"

# --- Edge keys, dev/CI fleet-root and the signed trust-anchor bundle ---------
EDGE_TOOL="${ROOT}/scripts/ci/edge-dev-keys.py"
PINS="${ROOT}/package/suderra-keys/suderra-edge-pins.py"

expect_fail() {
    local label="$1" pattern="$2"
    shift 2
    local out
    if out="$("$@" 2>&1)"; then
        echo "${label}: accepted" >&2
        exit 1
    fi
    grep -q -- "${pattern}" <<<"${out}" || {
        echo "${out}" >&2
        echo "${label}: rejected for the wrong reason" >&2
        exit 1
    }
}

# The bundle is a fleet-root-signed suderra.trust-anchors.v1 carrying the P0
# anchors (command, rbac-manifest, config-integrity, edge-release,
# edge-provisioning, mqtt-ca) and never fleet-root or device-lifecycle.
python3 -I - "${KEYS_DIR}/edge/trust-anchors.dsse.json" <<'PY'
import base64, json, sys
env = json.load(open(sys.argv[1], encoding="utf-8"))
assert env["payloadType"] == "application/vnd.suderra.trust-anchors.v1+json", env["payloadType"]
payload = json.loads(base64.b64decode(env["payload"], validate=True))
assert payload["_type"] == "suderra.trust-anchors.v1"
purposes = [a["purpose"] for a in payload["anchors"]]
assert purposes == ["command", "rbac-manifest", "config-integrity", "edge-release",
                    "edge-provisioning", "mqtt-ca"], purposes
PY

# Reruns keep the keys and the bundle byte for byte.
before="$(sha256sum "${KEYS_DIR}/edge/trust-anchors.dsse.json" "${KEYS_DIR}"/edge/*/1.pub)"
"${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
[ "${before}" = "$(sha256sum "${KEYS_DIR}/edge/trust-anchors.dsse.json" "${KEYS_DIR}"/edge/*/1.pub)" ]

# A tenant change re-signs with a higher bundle_seq (equal seq, other bytes
# is a replay to the device).
SUDERRA_EDGE_TENANT_IDS=11111111-2222-4333-8444-555555555555 \
    "${ROOT}/scripts/ci/prepare-ci-keyring.sh" "${KEYS_DIR}" >/dev/null
python3 -I - "${KEYS_DIR}/edge/trust-anchors.dsse.json" <<'PY'
import base64, json, sys
p = json.loads(base64.b64decode(json.load(open(sys.argv[1]))["payload"]))
assert p["tenant_scope"] == ["11111111-2222-4333-8444-555555555555"], p["tenant_scope"]
assert p["bundle_seq"] == 2, p["bundle_seq"]
PY

# Public-only sets keep no edge private key.
test -s "${PUBLIC_ONLY_DIR}/edge/trust-anchors.dsse.json"
if find "${PUBLIC_ONLY_DIR}" -type f -name '*.key' | grep -q .; then
    echo "public-only keyring kept an edge private key" >&2
    exit 1
fi

# Tampered, re-signed and planted bundles are rejected.
T="${TMPDIR}/tamper"
cp -a "${KEYS_DIR}" "${T}"
python3 -I - "${T}/edge/trust-anchors.dsse.json" <<'PY'
import base64, json, sys
path = sys.argv[1]
env = json.load(open(path))
p = json.loads(base64.b64decode(env["payload"]))
p["bundle_seq"] += 100
env["payload"] = base64.b64encode(json.dumps(p, sort_keys=True, separators=(",", ":")).encode()).decode()
json.dump(env, open(path, "w"))
PY
expect_fail "tampered bundle payload" "does not verify against fleet-root" \
    python3 -I "${EDGE_TOOL}" verify --keys-dir "${T}"

# DEC-3.7: an anchor bundle signed by the online provisioning key is refused.
T="${TMPDIR}/wrong-signer"
cp -a "${KEYS_DIR}" "${T}"
python3 -I - "${T}/edge" <<'PY'
import base64, hashlib, json, subprocess, sys, tempfile
from pathlib import Path
edge = Path(sys.argv[1])
path = edge / "trust-anchors.dsse.json"
env = json.load(open(path))
payload = base64.b64decode(env["payload"])
pt = env["payloadType"].encode()
key = edge / "edge-provisioning" / "1.key"
with tempfile.NamedTemporaryFile() as msg:
    msg.write(b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload))
    msg.flush()
    sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", msg.name],
                         capture_output=True, check=True).stdout
der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                     capture_output=True, check=True).stdout
env["signatures"] = [{"keyid": hashlib.sha256(der[-32:]).hexdigest(), "sig": base64.b64encode(sig).decode()}]
json.dump(env, open(path, "w"))
PY
expect_fail "bundle signed by the edge-provisioning key" "not signed by the fleet-root key" \
    python3 -I "${EDGE_TOOL}" verify --keys-dir "${T}"

T="${TMPDIR}/shared-key"
cp -a "${KEYS_DIR}" "${T}"
cp "${T}/edge/edge-provisioning/1.key" "${T}/edge/command/1.key"
cp "${T}/edge/edge-provisioning/1.pub" "${T}/edge/command/1.pub"
expect_fail "one key serving two purposes" "share one key" \
    python3 -I "${EDGE_TOOL}" verify --keys-dir "${T}"

T="${TMPDIR}/test-only"
cp -a "${KEYS_DIR}" "${T}"
cp "${ROOT}/contracts/suderra-edge/v1/test-keys/command-1.TEST-ONLY.pub" "${T}/edge/command/1.pub"
expect_fail "contract TEST-ONLY key in the edge keys" "TEST-ONLY" \
    python3 -I "${EDGE_TOOL}" verify --keys-dir "${T}"

expect_fail "edge keys for a prod profile" "dev and ci profiles only" \
    python3 -I "${EDGE_TOOL}" generate --keys-dir "${TMPDIR}/prod-edge" --profile prod

T="${TMPDIR}/prod-with-edge"
cp -a "${KEYS_DIR}" "${T}"
printf 'prod\n' > "${T}/suderra-keys.profile"
expect_fail "prod trust-root set carrying edge keys" "P1 key ceremony" \
    "${ROOT}/scripts/ci/validate-trust-roots.sh" "${T}" --expected-profile prod

# package/suderra-keys pins exactly the os-image purposes on dev images and
# nothing on production images.
TARGET="${TMPDIR}/target"
python3 -I "${PINS}" --trust-roots "${KEYS_DIR}" --target "${TARGET}" --variant dev >/dev/null
[ "$(cd "${TARGET}/etc/suderra/keys" && find . -type f | sort | tr '\n' ' ')" = \
    "./device-lifecycle/1.pub ./edge-provisioning/1.pub ./edge-release/1.pub ./fleet-root/1.pub " ]
cmp -s "${KEYS_DIR}/edge/fleet-root/1.pub" "${TARGET}/etc/suderra/keys/fleet-root/1.pub"
expect_fail "production image given edge keys" "none is inventoried yet" \
    python3 -I "${PINS}" --trust-roots "${KEYS_DIR}" --target "${TARGET}" --variant prod
T="${TMPDIR}/missing-purpose"
cp -a "${KEYS_DIR}" "${T}"
rm -rf "${T}/edge/device-lifecycle"
expect_fail "dev set without a device-lifecycle key" "device-lifecycle: no <epoch>.pub" \
    python3 -I "${PINS}" --trust-roots "${T}" --target "${TARGET}" --variant dev

# Every boards.json board image runs the root installer and so must carry it
# and its pinned keys (EI-023); the dev QEMU image also carries the swtpm EK
# reader and cryptsetup of DEC-8.10.
python3 -I - "${ROOT}" <<'PY'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
boards = json.loads((root / "contracts/suderra-edge/v1/boards.json").read_text())
def selected(defconfig):
    text = (root / "configs" / defconfig).read_text()
    # Kconfig reads only the first character of a bool value, so a trailing
    # comment after =y still selects the symbol.
    return set(re.findall(r"^(BR2_[A-Z0-9_]+)=y(?:\s|$)", text, re.M))
problems = []
for board in boards["boards"]:
    for image in board["os_images"]:
        have = selected(image["defconfig"])
        need = {"BR2_PACKAGE_SUDERRA_OS_INSTALLER", "BR2_PACKAGE_SUDERRA_KEYS"}
        if image["defconfig"] == "suderra_qemu_x86_64_defconfig":
            need |= {"BR2_PACKAGE_TPM2_TSS", "BR2_PACKAGE_TPM2_TOOLS", "BR2_PACKAGE_CRYPTSETUP"}
        problems += [f"{image['defconfig']} must select {s}" for s in sorted(need - have)]
if problems:
    sys.exit("\n".join(problems))
PY

# gen-dev-keys.sh makes a valid dev set with the same edge layout.
DEV_DIR="${TMPDIR}/dev"
bash "${ROOT}/scripts/gen-dev-keys.sh" "${DEV_DIR}" >/dev/null
"${ROOT}/scripts/ci/validate-trust-roots.sh" "${DEV_DIR}" --expected-profile dev --require-installer-signing

echo "CI keyring contract passed"
