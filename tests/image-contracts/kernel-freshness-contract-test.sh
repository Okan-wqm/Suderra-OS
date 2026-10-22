#!/usr/bin/env bash
#
# Kernel freshness check (EI-028): scripts/ci/check-kernel-freshness.py.
#
# The real check compares each kernel.org pin with kernel.org's list of the
# maintained series, so it needs the network and runs weekly
# (.github/workflows/kernel-freshness.yml). This test proves the logic on fixed
# release lists in the format kernel.org publishes, over a scratch copy of the
# defconfigs: the pins as they are, the boundary of the limit, one release past
# it, the pre-fix state (6.12.6, 108 releases behind), a series kernel.org
# dropped, an end-of-life series, a pin ahead of the list, an unreadable list,
# and a tree with no kernel.org pin at all. It also holds the workflow to
# running the check on a schedule with the default limit.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/ci/check-kernel-freshness.py"
WORKFLOW="${ROOT}/.github/workflows/kernel-freshness.yml"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECK}" ] || fail "missing ${CHECK}"

python3 -I - "${ROOT}" "${CHECK}" "${WORK}" << 'PY'
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
check = sys.argv[2]
work = Path(sys.argv[3])

pinned = {}
for path in sorted((root / "configs").glob("*_defconfig")):
    text = path.read_text(encoding="utf-8")
    match = re.search(r'^BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="([0-9.]+)"$', text, re.M)
    if match:
        pinned[path.name] = match.group(1)
if len(pinned) < 4:
    sys.exit(f"ERROR: expected the x86 and generic aarch64 defconfigs to pin kernel.org versions, found {sorted(pinned)}")
versions = set(pinned.values())
if len(versions) != 1:
    sys.exit(f"ERROR: the kernel.org pins differ ({sorted(pinned.items())}); one series.y per product line is the contract this test assumes")
version = versions.pop()
series = ".".join(version.split(".")[:2])
patch = int(version.split(".")[2])

LIMIT = 12


def release(moniker, ver, eol=False):
    return {"moniker": moniker, "version": ver, "iseol": eol, "released": {"isodate": "2026-10-21"}, "source": "x", "pgp": None}


def releases_file(name, entries):
    path = work / name
    path.write_text(json.dumps({"latest_stable": {"version": "7.2.12"}, "releases": entries}), encoding="utf-8")
    return path


def run(releases, tree=root, extra=()):
    return subprocess.run(
        ["python3", "-I", check, "--root", str(tree), "--releases-file", str(releases), *extra],
        capture_output=True, text=True,
    )


errors = []


def expect(label, result, status, needle):
    output = result.stdout + result.stderr
    if result.returncode != status:
        errors.append(f"{label}: exit {result.returncode}, expected {status}: {output.strip()}")
    elif needle not in output:
        errors.append(f"{label}: the output does not say {needle!r}: {output.strip()}")


other = [release("mainline", "7.3"), release("stable", "7.2.12"), release("longterm", "6.18.58"),
         release("longterm", "6.6.160"), release("linux-next", "next-20261021")]

# The pins as they are against a list whose latest is the pin: fresh, and every pinned defconfig reported.
fresh = releases_file("fresh.json", other + [release("longterm", version)])
result = run(fresh)
expect("fresh pins", result, 0, "kernel freshness passed")
for name in pinned:
    if f"{name}: kernel {version}" not in result.stdout:
        errors.append(f"{name} is not checked: the check silently skips a kernel.org pin")
if "vendor tree pinned by commit" not in result.stdout:
    errors.append("the vendor-tree defconfigs are not listed as not compared")

# The boundary: exactly the limit behind passes, one more fails.
boundary = releases_file("boundary.json", other + [release("longterm", f"{series}.{patch + LIMIT}")])
expect("exactly the limit behind", run(boundary), 0, f"{LIMIT} release(s) behind")
past = releases_file("past.json", other + [release("longterm", f"{series}.{patch + LIMIT + 1}")])
expect("one release past the limit", run(past), 1, "too stale")
expect("a tighter limit on the command line", run(boundary, extra=("--max-behind", str(LIMIT - 1))), 1, "too stale")

# The state EI-028 recorded: 6.12.6 against 6.12.114.
tree = work / "old-tree"
(tree / "configs").mkdir(parents=True)
for path in (root / "configs").glob("*_defconfig"):
    text = path.read_text(encoding="utf-8").replace(f'="{version}"', '="6.12.6"')
    (tree / "configs" / path.name).write_text(text, encoding="utf-8")
ei028 = releases_file("ei028.json", other + [release("longterm", "6.12.114")])
expect("the 6.12.6 pin of EI-028", run(ei028, tree), 1, "108 release(s) behind")

# A series kernel.org stopped listing, and one it lists as end-of-life.
gone = releases_file("gone.json", other)
expect("a dropped series", run(gone), 1, "no longer lists as maintained")
eol = releases_file("eol.json", other + [release("longterm", f"{series}.{patch}", eol=True)])
expect("an end-of-life series", run(eol), 1, "end-of-life")

# A pin newer than the list: the data or the pin is wrong.
ahead = releases_file("ahead.json", other + [release("longterm", f"{series}.{patch - 1}")])
expect("a pin ahead of the list", run(ahead), 1, "newer than the latest release")

# Unreadable lists are a different failure (exit 2), never a pass.
broken = work / "broken.json"
broken.write_text("{not json", encoding="utf-8")
expect("a list that is not JSON", run(broken), 2, "not JSON")
empty = releases_file("empty.json", [release("mainline", "7.3")])
expect("a list without stable series", run(empty), 2, "no stable or longterm series")
missing_key = work / "missing-key.json"
missing_key.write_text(json.dumps({"releases": [{"moniker": "longterm", "version": version}]}), encoding="utf-8")
expect("an entry without iseol", run(missing_key), 2, "has no 'iseol'")
duplicate = releases_file("duplicate.json", other + [release("longterm", version), release("stable", f"{series}.1")])
expect("a series listed twice", run(duplicate), 2, "listed twice")
expect("a missing list file", run(work / "does-not-exist.json"), 2, "does-not-exist.json")
plain = subprocess.run(["python3", "-I", check, "--root", str(root), "--releases-url", "file:///etc/passwd"], capture_output=True, text=True)
expect("a release list URL that is not https", plain, 2, "over https only")

# A tree that pins no kernel.org version would pass vacuously: it must not.
bare = work / "bare-tree"
(bare / "configs").mkdir(parents=True)
shutil.copy(root / "configs" / "suderra_aarch64_rpi4_defconfig", bare / "configs")
expect("no kernel.org pin at all", run(fresh, bare), 1, "would prove nothing")

if errors:
    print("\n".join(f"ERROR: {line}" for line in errors), file=sys.stderr)
    sys.exit(1)
print(f"kernel freshness logic: {len(pinned)} pins, series {series}, limit {LIMIT}")
PY

# The workflow runs it on a schedule, with the default limit, and does not
# swallow its status.
[ -f "${WORKFLOW}" ] || fail "missing ${WORKFLOW}"
python3 -I - "${WORKFLOW}" << 'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
errors = []
if not re.search(r"^  schedule:\n\s+- cron: ", text, re.M):
    errors.append("kernel-freshness.yml must run on a schedule: the check needs the live kernel.org list, so a pull request does not cover it")
if "workflow_dispatch:" not in text:
    errors.append("kernel-freshness.yml must be runnable on demand (workflow_dispatch)")
runs = re.findall(r"^\s+(?:run: )?(python3 -I scripts/ci/check-kernel-freshness\.py.*)$", text, re.M)
if len(runs) != 1:
    errors.append("kernel-freshness.yml must run scripts/ci/check-kernel-freshness.py exactly once")
elif "--max-behind" in runs[0] or "--releases-file" in runs[0] or "|| true" in text or "continue-on-error" in text:
    errors.append("kernel-freshness.yml must use the script's own limit and the live list, and must not ignore its status")
if "pull_request" in text or "push:" in text:
    errors.append("kernel-freshness.yml must not run on pull requests or pushes: an unrelated change would fail when kernel.org moves on")
if errors:
    print("\n".join(f"ERROR: {line}" for line in errors), file=sys.stderr)
    sys.exit(1)
PY

echo "kernel freshness contract passed"
