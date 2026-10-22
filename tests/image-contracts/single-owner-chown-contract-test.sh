#!/usr/bin/env bash
#
# Single ownership authority (ADR-048 DEC-4.2, DEC-4.3, DEC-24; EI-006).
#
# Owner and mode of every mutable tree come from two tmpfiles files and
# nowhere else:
#   /usr/lib/suderra/data-layout.tmpfiles.conf  /data trees, applied by
#                                               suderra-data-unlock after mount
#   /usr/lib/tmpfiles.d/suderra.conf            /run trees, at boot
# Both must state exactly what contracts/suderra-edge/v1/mutable-state.json
# states. Root never writes, chowns, chmods or mounts inside the trees the
# agent writes (symlink-race rule): no runtime root script or unit names an
# agent tree together with a writing command, and no Buildroot package
# declares their ownership a second time.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
OVERLAY="${ROOT}/board/suderra/common/rootfs-overlay"
CONTRACT="${ROOT}/contracts/suderra-edge/v1/mutable-state.json"

python3 -I - "${CONTRACT}" "${OVERLAY}" <<'PY'
import json
import re
import sys
from pathlib import Path, PurePosixPath

contract = json.load(open(sys.argv[1], encoding="utf-8"))
overlay = Path(sys.argv[2])
errors = []

def tmpfiles(path):
    lines = {}
    for raw in (overlay / path.lstrip("/")).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 6 or fields[5] != "-":
            errors.append(f"{path}: not a 'type path mode user group -' line: {raw!r}")
            continue
        kind, p, mode, user, group, _ = fields
        if p in lines:
            errors.append(f"{path}: {p} appears twice")
        lines[p] = (kind, mode, user, group)
    return lines

data_layout = contract["data_partition"]["layout_tmpfiles"]
run_tmpfiles = contract["run_tmpfiles"]
entries = contract["entries"]

# /data: every /data-backed directory of the contract, with its owner and mode.
expected_data = {}
for e in entries:
    kind = e["backing"]["kind"]
    if kind in ("data-bind", "data-dir", "data-layout-dir") and e["node"] == "directory":
        expected_data[e["backing"]["source"]] = ("d", e["mode"], e["owner"], e["group"])
# Parents between /data and a listed tree must exist; they are root:root 0755.
for source in list(expected_data):
    for parent in PurePosixPath(source).parents:
        p = str(parent)
        if p in ("/", "/data") or p in expected_data:
            continue
        expected_data.setdefault(p, ("d", "0755", "root", "root"))
got_data = tmpfiles(data_layout)
if got_data != expected_data:
    for p in sorted(set(expected_data) | set(got_data)):
        if expected_data.get(p) != got_data.get(p):
            errors.append(f"{data_layout}: {p}: contract {expected_data.get(p)}, file {got_data.get(p)}")

# /run: tmpfs directories of the contract; a tmpfs-bind directory is created
# at its source, and entries below it at the corresponding source path.
binds = {
    e["path"]: e["backing"]["source"]
    for e in entries
    if e["backing"]["kind"] == "tmpfs-bind" and e["node"] == "directory"
}
expected_run = {}
for e in entries:
    kind = e["backing"]["kind"]
    if e["node"] != "directory" or kind not in ("tmpfs", "tmpfs-bind"):
        continue
    path = e["path"]
    if path.startswith("/run/systemd/"):
        continue  # systemd's own runtime tree
    if kind == "tmpfs-bind":
        path = e["backing"]["source"]
    else:
        for target, source in binds.items():
            if path.startswith(target + "/"):
                path = source + path[len(target):]
    expected_run[path] = ("d", e["mode"], e["owner"], e["group"])
# The update lock shared by agent and OS updates (DEC-2.3) must exist before
# the sandboxed worker opens it; mutable-state.json does not list it yet
# (reported contract gap), so it is the one extra line, with a fixed shape.
expected_run["/run/suderra-update.lock"] = ("f", "0600", "root", "root")
got_run = tmpfiles(run_tmpfiles)
if got_run != expected_run:
    for p in sorted(set(expected_run) | set(got_run)):
        if expected_run.get(p) != got_run.get(p):
            errors.append(f"{run_tmpfiles}: {p}: contract {expected_run.get(p)}, file {got_run.get(p)}")

# Agent-writable trees, as the contract names them (owner = the agent).
agent_trees = sorted(
    {e["path"] for e in entries if e.get("writer") == "agent"}
    | {e["backing"]["source"] for e in entries if e.get("writer") == "agent" and "source" in e["backing"]}
)
agent_re = re.compile("(" + "|".join(re.escape(t) for t in agent_trees) + r")(?![-\w])")
write_re = re.compile(
    r"\b(chown|chgrp|chmod|mkdir|touch|install|mv|cp|rm|ln|tee|truncate|dd|mkfifo|mknod|setfacl)\b|>|\bsed\s+-i\b"
)
runtime_files = sorted(
    [p for p in (overlay / "usr/sbin").iterdir() if p.is_file()]
    + [p for p in (overlay / "etc/systemd/system").rglob("*") if p.is_file()]
)
for f in runtime_files:
    if f.name == "suderra-agent.service" or f.parent.name == "suderra-agent.service.d":
        continue  # the agent's own unit grants it its trees
    for number, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or not agent_re.search(line):
            continue
        if write_re.search(line):
            errors.append(f"{f.relative_to(overlay)}:{number}: root writes inside an agent tree: {stripped}")
    text = f.read_text(encoding="utf-8")
    for m in re.finditer(r"^\s*ReadWritePaths=(.*)$", text, re.M):
        for p in m.group(1).split():
            if agent_re.search(p.lstrip("-")):
                errors.append(f"{f.relative_to(overlay)}: a root unit makes the agent tree {p} writable")

for e in errors:
    print(f"ERROR: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
PY

# No Buildroot package declares ownership of the agent trees a second time
# (the removed edge-agent package did, EI-006).
if grep -R -n -E '/var/lib/suderra([^-]|$)|/var/log/suderra' "${ROOT}/package" --include='*.mk'; then
    echo "ERROR: a package declares ownership of an agent tree; data-layout.tmpfiles.conf is the only authority" >&2
    exit 1
fi

# suderra-data-unlock applies the data layout and never chowns or chmods.
UNLOCK="${OVERLAY}/usr/sbin/suderra-data-unlock"
# shellcheck disable=SC2016 # the literal script text is matched
grep -q 'systemd-tmpfiles --create "${LAYOUT}"' "${UNLOCK}" ||
    { echo "ERROR: suderra-data-unlock must apply data-layout.tmpfiles.conf" >&2; exit 1; }
grep -q '^LAYOUT=/usr/lib/suderra/data-layout.tmpfiles.conf$' "${UNLOCK}" ||
    { echo "ERROR: suderra-data-unlock must apply /usr/lib/suderra/data-layout.tmpfiles.conf" >&2; exit 1; }
# shellcheck disable=SC2016 # the literal script text is matched
if grep -nE '^[^#]*\b(chown|chgrp|chmod)\b' "${UNLOCK}" | grep -v 'chmod 0600 "${TEMP}"'; then
    echo "ERROR: suderra-data-unlock must leave ownership to data-layout.tmpfiles.conf" >&2
    exit 1
fi

echo "single ownership authority contract passed"
