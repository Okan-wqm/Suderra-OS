#!/usr/bin/env bash
#
# The results root's shell helpers write are results the contract accepts
# (ADR-048 DEC-27, EI-084).
#
# suderra-lockdown, suderra-data-unlock and suderra-time-state record their
# outcome with `suderra-installer result write --kind K --outcome O --reason R`.
# The installer validates every document against the contract's result schema
# and refuses an invalid one, which records nothing: a script that names a reason
# the schema does not allow for its kind loses the technician-visible result of
# exactly the failure it describes. suderra-lockdown did that for an open
# technician path (reason state-corrupt, which belongs to the lifecycle store).
#
# scripts/ci/check-result-reasons.py reads the vendored result schema and holds
# every `result write` of the image, and every literal passed to the shell
# functions that forward to it, to the kind's reason list. This test runs it on
# the repository, asserts what it found (so a checker that stopped finding the
# call sites cannot pass), and proves on a scratch copy that it fails for every
# class of defect it exists to catch, including a change of the schema alone.
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="${ROOT}/scripts/ci/check-result-reasons.py"
SBIN="board/suderra/common/rootfs-overlay/usr/sbin"
SCHEMA="contracts/suderra-edge/v1/schemas/result.schema.json"
LOCKDOWN="${SBIN}/suderra-lockdown"
UNLOCK="${SBIN}/suderra-data-unlock"
TIMESTATE="${SBIN}/suderra-time-state"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[ -f "${CHECK}" ] || fail "missing ${CHECK}"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# 1. The repository itself.
python3 -I -B "${CHECK}" --root "${ROOT}" ||
    fail "a result script of the image writes a result the contract does not accept"
python3 -I -B "${CHECK}" --root "${ROOT}" --json >"${WORK}/found.json"
python3 -I - "${WORK}/found.json" "${SBIN}" <<'PY'
import json
import sys

found = json.load(open(sys.argv[1]))
sbin = sys.argv[2]
failures = []


def expect(script, kind, reasons, sites_at_least):
    entry = found.get(f"{sbin}/{script}")
    if entry is None:
        failures.append(f"{script}: the checker found no result written")
        return
    got = entry["kinds"].get(kind)
    if got is None or set(got) != set(reasons):
        failures.append(f"{script}: {kind} reasons {got}, expected exactly {sorted(reasons)}")
    if entry["sites"] < sites_at_least:
        failures.append(f"{script}: {entry['sites']} call sites found, expected at least {sites_at_least}")
    if set(entry["kinds"]) != {kind}:
        failures.append(f"{script}: writes kinds {sorted(entry['kinds'])}, expected only {kind}")


# What each script reports today. A new reason is a reviewed change of this table,
# and of the contract if the schema does not have it yet.
expect("suderra-lockdown", "lockdown",
       ["firewall-load-failed", "io-error", "lifecycle-inconsistent", "provisioning-mode-active"], 6)
expect("suderra-data-unlock", "data-unlock", ["data-unmountable", "io-error", "tpm-unseal-failed"], 20)
expect("suderra-time-state", "time-state", ["clock-below-floor", "clock-unsynced"], 4)
for script in sorted(found):
    if not script.startswith(sbin + "/"):
        failures.append(f"{script}: a result producer outside {sbin}; extend this table")
if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
PY
! grep -q 'state-corrupt' "${ROOT}/${LOCKDOWN}" ||
    fail "suderra-lockdown names state-corrupt, a reason of the lifecycle store that the schema refuses for a lockdown result"
echo "  the image's result scripts write only reasons the schema allows"

# 2. Mutations on a scratch copy: each class of defect must fail the checker.
fresh() {
    rm -rf "${WORK}/tree"
    mkdir -p "${WORK}/tree/${SBIN}" "${WORK}/tree/$(dirname "${SCHEMA}")"
    cp "${ROOT}/${SCHEMA}" "${WORK}/tree/${SCHEMA}"
    for script in "${LOCKDOWN}" "${UNLOCK}" "${TIMESTATE}"; do
        cp "${ROOT}/${script}" "${WORK}/tree/${script}"
    done
}

# expect_failure NAME PATTERN: the checker must exit non-zero and say PATTERN.
expect_failure() {
    local name="$1" pattern="$2" out
    if out="$(python3 -I -B "${CHECK}" --root "${WORK}/tree" 2>&1)"; then
        fail "mutation '${name}' was accepted"
    fi
    printf '%s\n' "${out}" | grep -qE -- "${pattern}" ||
        fail "mutation '${name}' failed for the wrong reason (wanted /${pattern}/): ${out}"
    echo "  rejected: ${name}"
}

mutate() {
    # mutate FILE OLD NEW: replace exactly one occurrence, or the mutation is stale.
    python3 -I - "${WORK}/tree/$1" "$2" "$3" <<'PY'
import sys

path, old, new = sys.argv[1:4]
text = open(path, encoding="utf-8").read()
if text.count(old) < 1:
    sys.exit(f"the mutation anchor {old!r} is not in {path}")
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
}

fresh
python3 -I -B "${CHECK}" --root "${WORK}/tree" || fail "the scratch copy is not a clean baseline"

fresh
mutate "${LOCKDOWN}" 'failed provisioning-mode-active "dropbear' 'failed state-corrupt "dropbear'
expect_failure "lockdown reports the lifecycle store's reason (EI-084)" "state-corrupt.*not allowed for a 'lockdown' result"

fresh
mutate "${UNLOCK}" 'alarm data-unmountable "cannot mount' 'alarm clock-unsynced "cannot mount'
expect_failure "data-unlock reports a time reason" "clock-unsynced.*not allowed for a 'data-unlock' result"

fresh
mutate "${TIMESTATE}" 'alarm_once clock-unsynced' 'alarm_once io-error'
expect_failure "time-state alarm with a reason of another kind, through two forwarding functions" \
    "io-error.*not allowed for a 'time-state' result"

fresh
printf '"${INSTALLER}" result write --kind lockdown --outcome failed --reason bogus-reason\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "a literal reason the schema does not know" "bogus-reason.*not allowed"

fresh
mutate "${LOCKDOWN}" '--kind lockdown --outcome ok' '--kind lock-down --outcome ok'
expect_failure "an unknown kind" "unknown result kind 'lock-down'"

fresh
printf '"${INSTALLER}" result write --kind site-config --outcome ok\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "a kind whose result must name its statement" "must name the statement"

fresh
printf '"${INSTALLER}" result write --kind lockdown --outcome ok --reason io-error\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "an ok result with a reason" "outcome ok carries the reason"

fresh
printf '"${INSTALLER}" result write --kind lockdown --outcome failed\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "a failure without a reason" "outcome failed carries no reason"

fresh
printf '"${INSTALLER}" result write --kind lockdown --outcome exploded --reason io-error\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "an unknown outcome" "unknown outcome 'exploded'"

fresh
printf 'why=io-error\n"${INSTALLER}" result write --kind lockdown --outcome failed --reason "${why}"\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "a reason in a variable nobody can trace" "cannot be traced to a literal"

fresh
mutate "${LOCKDOWN}" 'failed lifecycle-inconsistent "lockdown follows' 'failed "${state}" "lockdown follows'
expect_failure "a helper called with a variable reason" "cannot be traced to a literal"

fresh
printf '\nstray() {\n    "${INSTALLER}" result write --kind lockdown --outcome failed --reason "$1"\n}\n' >>"${WORK}/tree/${LOCKDOWN}"
expect_failure "a forwarding function nothing calls" "function stray forwards a reason .* nothing calls it"

fresh
mutate "${LOCKDOWN}" '--kind lockdown --outcome failed' '--kind lockdown --outcome failed --subject x'
expect_failure "an argument the writer does not take" "unknown argument '--subject'"

# The schema alone decides: the unchanged, correct script fails when the schema stops
# listing the reason it reports.
fresh
python3 -I - "${WORK}/tree/${SCHEMA}" <<'PY'
import json
import sys

path = sys.argv[1]
schema = json.load(open(path))
for branch in schema["allOf"]:
    if branch["if"]["properties"]["kind"]["const"] == "lockdown":
        enum = branch["then"]["properties"]["reason"]["enum"]
        enum.remove("provisioning-mode-active")
json.dump(schema, open(path, "w"))
PY
expect_failure "the schema no longer allows provisioning-mode-active for a lockdown" \
    "provisioning-mode-active.*not allowed for a 'lockdown' result"

# A checker that finds nothing must not pass.
fresh
rm -f "${WORK}/tree/${LOCKDOWN}" "${WORK}/tree/${UNLOCK}" "${WORK}/tree/${TIMESTATE}"
expect_failure "no producer found at all" "no script of the image writes a result"

echo "result reasons contract passed"
