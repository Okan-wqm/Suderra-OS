#!/usr/bin/env bash
#
# /etc/suderra/board and /etc/suderra/features on every image (ADR-048
# DEC-8.2, DEC-8.4, DEC-6.8; EI-018).
#
# Board identity is a build-time fact of the signed image, never a runtime
# probe: post-build.sh writes /etc/suderra/board from the vendored
# boards.json for every image boards.json lists as a board's image, and
# writes none for the images that declare no board. The declared features
# the health predicate checks are a fact of every image, board or not, and
# live in /etc/suderra/features only. Every image with a board also carries
# /etc/suderra/cloud-endpoint, the https base URL of the provisioning API
# (DEC-5.5), so `edge provision` has somewhere to fetch from. This runs
# post-build's image-facts section for every defconfig and checks the files
# against boards.json and the defconfig, as the root installer does again at
# run time.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

grep -q '^# 6\. Image facts' "${POST_BUILD}" || fail "post-build.sh has no image-facts section"
grep -q '^# RAUC compatible (ADR-048 DEC-8.3)' "${POST_BUILD}" || fail "post-build.sh has no RAUC compatible section"
if grep -rn 'device-tree/model\|detect_board\|SUDERRA_TARGET_BOARD' \
    "${ROOT}/board/suderra/common/rootfs-overlay" "${ROOT}/userspace/suderra-installer/src"; then
    fail "board identity must not be probed at run time on the edge path (DEC-8.2)"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
# The section locates the external tree from its own path (../../..).
mkdir -p "${WORK}/ext/board/suderra/common"
ln -s "${ROOT}/contracts" "${WORK}/ext/contracts"
SECTION="${WORK}/ext/board/suderra/common/image-facts.sh"
sed -n '/^# 6\. Image facts/,/^# RAUC compatible (ADR-048 DEC-8\.3)/p' "${POST_BUILD}" > "${SECTION}"

checked=0
for defconfig_path in "${ROOT}"/configs/*_defconfig; do
    defconfig="$(basename "${defconfig_path}")"
    target="${WORK}/target-${defconfig}"
    mkdir -p "${target}/etc"
    variant=dev
    grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${defconfig_path}" && variant=prod
    (
        export TARGET_DIR="${target}" DEFCONFIG_NAME="${defconfig%_defconfig}"
        export SUDERRA_OS_VARIANT="${variant}" BR2_CONFIG="${defconfig_path}"
        # shellcheck disable=SC1090
        source "${SECTION}"
    ) >"${WORK}/log" 2>&1 || { cat "${WORK}/log" >&2; fail "${defconfig}: image-facts section failed"; }

    python3 -I - "${ROOT}/contracts/suderra-edge/v1/boards.json" "${defconfig}" "${target}" "${variant}" "${defconfig_path}" <<'PY'
import json, re, sys
from pathlib import Path
boards_path, defconfig, target, variant, defconfig_path = sys.argv[1:]
boards = json.load(open(boards_path, encoding="utf-8"))
board_file = Path(target) / "etc/suderra/board"
features_file = Path(target) / "etc/suderra/features"
endpoint_file = Path(target) / "etc/suderra/cloud-endpoint"

def env_file(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line)
        if not m:
            sys.exit(f"{defconfig}: malformed line {line!r} in {path.name}")
        values[m.group(1)] = m.group(2).strip('"')
    return values

# Features: every image, one FEATURES line, following the defconfig.
if not features_file.is_file():
    sys.exit(f"{defconfig}: no /etc/suderra/features")
declared = env_file(features_file)
if set(declared) != {"FEATURES"}:
    sys.exit(f"{defconfig}: /etc/suderra/features holds only FEATURES, got {sorted(declared)}")
features = set(declared["FEATURES"].split())
allowed = {"verity", "secure-boot", "rauc", "tpm", "luks"}
if not features <= allowed:
    sys.exit(f"{defconfig}: undeclared features {sorted(features - allowed)}")
selected = set(re.findall(r"^(BR2_[A-Za-z0-9_]+)=y(?:\s|$)", Path(defconfig_path).read_text(), re.M))
if ("rauc" in features) != ("BR2_PACKAGE_RAUC" in selected):
    sys.exit(f"{defconfig}: FEATURES rauc must follow BR2_PACKAGE_RAUC")
if variant == "prod" and not {"verity", "luks"} <= features:
    sys.exit(f"{defconfig}: a production image declares verity and luks")
if variant == "prod" and ("secure-boot" in features) != ("BR2_x86_64" in selected):
    sys.exit(f"{defconfig}: a production x86_64 image, and only one, declares secure-boot")
if variant == "dev" and features & {"verity", "luks", "secure-boot"}:
    sys.exit(f"{defconfig}: a dev image declares no verity, luks or secure-boot")

rows = [b for b in boards["boards"] if any(i["defconfig"] == defconfig for i in b["os_images"])]
if not rows:
    if board_file.exists():
        sys.exit(f"{defconfig} declares no board in boards.json but got {board_file}")
    if endpoint_file.exists():
        sys.exit(f"{defconfig} declares no board but got {endpoint_file}")
    if "tpm" in features:
        sys.exit(f"{defconfig}: an image without a board has no TPM device binding")
    sys.exit(0)
b = rows[0]
if not board_file.is_file():
    sys.exit(f"{defconfig}: no /etc/suderra/board for board {b['board_profile']}")
values = env_file(board_file)
want = {
    "BOARD_PROFILE": b["board_profile"],
    "ARCH": b["arch"],
    "RAUC_COMPATIBLE": b["rauc_compatible"],
    "DEVICE_BINDING_METHOD": b["device_binding_method"],
}
if set(values) != set(want):
    sys.exit(f"{defconfig}: board file keys {sorted(values)}, want {sorted(want)} (FEATURES lives in /etc/suderra/features)")
for key, value in want.items():
    if values.get(key) != value:
        sys.exit(f"{defconfig}: {key}={values.get(key)!r}, boards.json says {value!r}")
tpm_bound = b["device_binding_method"] == "tpm-ek-sha256" and "BR2_PACKAGE_TPM2_TOOLS" in selected
if ("tpm" in features) != tpm_bound:
    sys.exit(f"{defconfig}: FEATURES tpm must follow a TPM-EK binding with tpm2-tools")
if not endpoint_file.is_file():
    sys.exit(f"{defconfig}: no /etc/suderra/cloud-endpoint for board {b['board_profile']}")
endpoint = endpoint_file.read_text(encoding="utf-8")
if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%!$&()*+,;=:@/-]*[^/])?\n", endpoint):
    sys.exit(f"{defconfig}: cloud endpoint {endpoint!r} is not one https base URL line")
fake_cloud = endpoint.startswith("https://10.0.2.2:")
if (b["role"] == "ci") != fake_cloud:
    sys.exit(f"{defconfig}: only ci-role boards (the QEMU targets) point at the QEMU fake cloud, got {endpoint.strip()}")
PY
    checked=$((checked + 1))
done
[ "${checked}" -ge 9 ] || fail "only ${checked} defconfigs checked"
echo "board and features file contract passed (${checked} defconfigs)"
