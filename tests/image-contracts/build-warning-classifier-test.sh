#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/upstream.log" <<'LOG'
../../gcc/c/c-typeck.cc:3798:17: warning: format not a string literal and no format arguments [-Wformat-security]
../../gcc/expmed.cc:1838:45: warning: may be used uninitialized [-Wmaybe-uninitialized]
../../c++tools/server.cc:620:10: warning: ignoring return value [-Wunused-result]
../../../../libsanitizer/asan/asan_interceptors.cpp:134:5: warning: ISO C++ forbids braced-groups within expressions [-Wpedantic]
gengtype-lex.cc:356:15: warning: this statement may fall through [-Wimplicit-fallthrough=]
plural.y:51.1-7: warning: POSIX Yacc does not support %define [-Wyacc]
libtool: install: warning: remember to run `libtool --finish /tmp/example'
configure: WARNING: using cross tools not prefixed with host triplet
>>> host-flex 2.6.4 Building
parse.y:360:41: warning: '%s' directive output may be truncated [-Wformat-truncation=]
scan.c:8390:13: warning: conflicting types for built-in function 'malloc' [-Wbuiltin-declaration-mismatch]
make[1]: Entering directory '/workspace/buildroot/support/kconfig'
./util.c:86:26: warning: '%s' directive writing 10 or more bytes into a region of size between 1 and 4097 [-Wformat-overflow=]
LOG

python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --json-output "${TMP_DIR}/upstream-warnings.json" \
    "${TMP_DIR}/upstream.log" >/dev/null

python3 - "${TMP_DIR}/upstream-warnings.json" "${TMP_DIR}/upstream-policy.json" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1], encoding="utf-8").read())
policy = {
    "schema_version": "suderra.build-warning-policy.v1",
    "known_upstream": {
        "owner": "build-platform",
        "expires_at": "2099-01-01T00:00:00Z",
        "allowed_fingerprints": sorted(evidence["fingerprints"]),
    },
    "third_party": {"fail": True},
}
open(sys.argv[2], "w", encoding="utf-8").write(json.dumps(policy, indent=2) + "\n")
PY

python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${TMP_DIR}/upstream-policy.json" \
    --json-output "${TMP_DIR}/upstream-warnings.json" \
    "${TMP_DIR}/upstream.log" >/dev/null

python3 - "${TMP_DIR}/upstream-warnings.json" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert evidence["summary"] == {"known-upstream": 11, "owned": 0, "third-party": 0}
assert evidence["unique_fingerprints"] == 11
assert not evidence["failing"]
PY

cat > "${TMP_DIR}/owned.log" <<'LOG'
/workspace/package/suderra-os-installer/suderra-os-install:12: warning: unsafe shell expansion
/workspace/.github/workflows/build.yml:12: warning: skipped gate
>>> suderra-os-installer 1.0 Building
src/lib.rs:12:3: warning: owned package relative warning
LOG

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" "${TMP_DIR}/owned.log" >/dev/null 2>&1; then
    echo "ERROR: owned Suderra warning was not rejected" >&2
    exit 1
fi

cat > "${TMP_DIR}/build-env.log" <<'LOG'
>>> dbus 1.14.10 Installing to target
chown: invalid group: 'root:dbus'
LOG

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" "${TMP_DIR}/build-env.log" >/dev/null 2>&1; then
    echo "ERROR: build environment install failure was not rejected" >&2
    exit 1
fi

cat > "${TMP_DIR}/third-party.log" <<'LOG'
/workspace/output/build/example-1.0/main.c:1:2: warning: third-party warning
LOG

python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" "${TMP_DIR}/third-party.log" >/dev/null

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" --fail-third-party "${TMP_DIR}/third-party.log" >/dev/null 2>&1; then
    echo "ERROR: --fail-third-party did not reject unclassified warning" >&2
    exit 1
fi

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${PROJECT_ROOT}/ci/build-warning-policy.json" \
    "${TMP_DIR}/third-party.log" >/dev/null 2>&1; then
    echo "ERROR: warning policy did not reject unclassified third-party warning" >&2
    exit 1
fi

cat > "${TMP_DIR}/new-upstream.log" <<'LOG'
>>> busybox 1.36.1 Building
applets/applets.c:42:2: warning: new upstream warning requiring triage [-Wformat]
LOG

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${TMP_DIR}/upstream-policy.json" \
    "${TMP_DIR}/new-upstream.log" >/dev/null 2>&1; then
    echo "ERROR: warning policy did not reject an unapproved known-upstream fingerprint" >&2
    exit 1
fi

cat > "${TMP_DIR}/expired-policy.json" <<'JSON'
{
  "schema_version": "suderra.build-warning-policy.v1",
  "known_upstream": {
    "owner": "build-platform",
    "expires_at": "2000-01-01T00:00:00Z",
    "allowed_fingerprints": []
  },
  "third_party": {
    "fail": true
  }
}
JSON

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${TMP_DIR}/expired-policy.json" \
    "${TMP_DIR}/upstream.log" >/dev/null 2>&1; then
    echo "ERROR: expired warning policy unexpectedly passed" >&2
    exit 1
fi
