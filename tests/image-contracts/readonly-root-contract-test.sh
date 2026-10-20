#!/usr/bin/env bash
#
# Read-only root mutable-state contract (ADR-048 DEC-4.9, DEC-24, DEC-5.2;
# contracts/suderra-edge/v1/mutable-state.json; EI-026).
#
# The production root is a read-only dm-verity mount with no /etc or /var
# overlay, so nothing may write the root at run time. Every path that changes
# is in mutable-state.json, and this test checks the image sources against it:
#   * production defconfigs never remount the root rw;
#   * every /data-backed tree has a mountpoint built into the image and is
#     bound by suderra-data-unlock with the contract's options, /data itself
#     is nosuid,nodev,noexec and the release bind is the only exec mount;
#   * /etc/shadow changes only by suderra-provision-mode's /run bind, the
#     worker's scratch space is its RuntimeDirectory=, /etc/dropbear is a
#     /data bind;
#   * no runtime script or unit writes under /etc, masks a unit persistently
#     or makes /etc writable;
#   * /etc/machine-id ships empty, nothing Suderra reads it, the journal is
#     volatile.
# The dynamic half (EROFS in the boot journal of the production QEMU image)
# is the P1 prod-QEMU lane; P0 runs the production units' sandboxes in
# tests/qemu/edge-readonly-sandbox-test.py.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
CONTRACT="${ROOT}/contracts/suderra-edge/v1/mutable-state.json"
POST_BUILD="${ROOT}/board/suderra/common/post-build.sh"
UNLOCK="${OVERLAY}/usr/sbin/suderra-data-unlock"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# Production defconfigs: the root is never remounted rw.
for defconfig in "${ROOT}"/configs/*_defconfig; do
    grep -q '^BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${defconfig}" || continue
    grep -qx '# BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW is not set' "${defconfig}" ||
        fail "$(basename "${defconfig}") must not remount the read-only root rw (BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW=n)"
done

python3 -I - "${CONTRACT}" "${OVERLAY}" "${POST_BUILD}" "${UNLOCK}" <<'PY'
import json
import re
import sys
from pathlib import Path

contract = json.load(open(sys.argv[1], encoding="utf-8"))
overlay = Path(sys.argv[2])
post_build = Path(sys.argv[3]).read_text(encoding="utf-8")
unlock = Path(sys.argv[4]).read_text(encoding="utf-8")
errors = []

rootfs = contract["rootfs"]
if rootfs["buildroot_remount_rootfs_rw"] or rootfs["etc_runtime_writes"]:
    errors.append("mutable-state.json no longer describes a read-only root")

# /data mount options.
options = contract["data_partition"]["mount_options"]
m = re.search(r"^DATA_OPTIONS=(\S+)$", unlock, re.M)
if not m or m.group(1).split(",") != options:
    errors.append(f"suderra-data-unlock must mount /data with {','.join(options)}")
if 'mount -o "${DATA_OPTIONS}"' not in unlock:
    errors.append("suderra-data-unlock must mount /data with DATA_OPTIONS")

# Every data-bind tree: built-in mountpoint, bound with the contract options.
binds = dict(
    (src, (target, opts))
    for src, target, opts in re.findall(r'^\s*bind_tree (\S+) (\S+) "([^"]+)"$', unlock, re.M)
)
for e in contract["entries"]:
    backing = e["backing"]
    if backing["kind"] != "data-bind":
        continue
    path, source = e["path"], backing["source"]
    if not re.search(rf"^\s+{re.escape(path)}( \\)?$", post_build, re.M) and path != "/etc/dropbear":
        errors.append(f"post-build.sh does not create the mountpoint {path}")
    if source not in binds or binds[source][0] != path:
        errors.append(f"suderra-data-unlock does not bind {source} onto {path}")
        continue
    got = set(binds[source][1].replace("${DATA_OPTIONS}", ",".join(options)).split(","))
    want = set(backing.get("mount_options", [])) or set(options)
    if "exec" in want:
        want = want - {"noexec"}
    else:
        want = want | set(options)
    if got != want:
        errors.append(f"{path}: bound with {sorted(got)}, contract {sorted(want)}")
exec_binds = [s for s, (_, o) in binds.items() if re.search(r"(^|,)exec(,|$)", o)]
if exec_binds != ["/data/suderra/edge"]:
    errors.append(f"the only exec mount on /data is the release bind, found {exec_binds}")

# /etc/dropbear is a real directory in the image, bound from /data.
if 'rm -f "${TARGET_DIR}/etc/dropbear"' not in post_build:
    errors.append("post-build.sh must replace Buildroot's /etc/dropbear symlink with a mountpoint")

# /etc/shadow: only suderra-provision-mode binds over it.
for f in sorted((overlay / "usr/sbin").iterdir()):
    for number, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if re.search(r"mount\s+--bind\s+\S+\s+/etc/shadow\b", line) and f.name != "suderra-provision-mode":
            errors.append(f"usr/sbin/{f.name}:{number}: only suderra-provision-mode binds /etc/shadow")

# The worker's scratch space is its RuntimeDirectory=.
worker = (overlay / "etc/systemd/system/suderra-provision-worker.service").read_text(encoding="utf-8")
if not re.search(r"^RuntimeDirectory=suderra-installer$", worker, re.M):
    errors.append("suderra-provision-worker.service must create /run/suderra-installer with RuntimeDirectory=")

# No runtime write under /etc.
etc_write = re.compile(
    r"(>>?\s*\"?/etc/)|(\bsed\s+-i\b.*/etc/)|(\b(touch|mkdir|rm|mv|cp|ln|install|chmod|chown|tee)\b[^|;]*\s\"?/etc/)"
    r"|(\bsystemctl\b(?!.*--runtime).*\bmask\b)|(\bpasswd\s+-l\b)|(\bchpasswd\b)|(\bsystemd-machine-id-setup\b)"
)
for f in sorted((overlay / "usr/sbin").iterdir()):
    for number, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if etc_write.search(line):
            errors.append(f"usr/sbin/{f.name}:{number}: writes the read-only root: {line.strip()}")
for f in sorted((overlay / "etc/systemd/system").rglob("*")):
    if not f.is_file():
        continue
    text = f.read_text(encoding="utf-8")
    for m in re.finditer(r"^\s*ReadWritePaths=(.*)$", text, re.M):
        for p in m.group(1).split():
            if p.lstrip("-").startswith("/etc"):
                errors.append(f"{f.relative_to(overlay)}: ReadWritePaths= makes {p} writable")
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("Exec") and etc_write.search(line):
            errors.append(f"{f.relative_to(overlay)}:{number}: writes the read-only root: {line.strip()}")

# machine-id: empty in the image, never read by Suderra code.
if ': > "${TARGET_DIR}/etc/machine-id"' not in post_build:
    errors.append("post-build.sh must ship /etc/machine-id as an empty file")
for f in sorted((overlay / "usr/sbin").iterdir()) + sorted((overlay / "etc/systemd/system").rglob("*")):
    if not f.is_file():
        continue
    for number, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip().startswith("#") and "machine-id" in line:
            errors.append(f"{f.relative_to(overlay)}:{number}: reads /etc/machine-id (DEC-4.9)")

# Volatile journal.
journald = overlay / "etc/systemd/journald.conf.d/10-suderra-volatile.conf"
text = journald.read_text(encoding="utf-8") if journald.exists() else ""
if not re.search(r"^Storage=volatile$", text, re.M) or not re.search(r"^RuntimeMaxUse=\S+$", text, re.M):
    errors.append("journald must run with Storage=volatile and a bounded RuntimeMaxUse=")

for e in errors:
    print(f"ERROR: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY

echo "read-only root contract passed"
