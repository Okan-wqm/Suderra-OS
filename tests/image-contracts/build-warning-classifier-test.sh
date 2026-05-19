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
:51.1-7: warning: POSIX Yacc does not support %define [-Wyacc]
.1-7: warning: POSIX Yacc does not support %define [-Wyacc]
libtool: install: warning: remember to run `libtool --finish /tmp/example'
libtool: install: warning: remember to run `libtool --finish /workspace/output/foo_defconfig/per-package/host-gcc-final/host/libexec/gcc/aarch64-buildroot-linux-gnu/13.3.0'
libtool: install: warning: remember to run `libtool --finish ../output/bar_defconfig/per-package/host-gcc-final/host/libexec/gcc/aarch64-buildroot-linux-gnu/13.3.0'
checking if /tmp/tool supports -c -o file.o... libtool: link: warning: `-version-info/-version-number' is ignored for convenience libraries
libtool: link: warning: `-version-info/-version-number' is ignored for convenience libraries
configure: WARNING: using cross tools not prefixed with host triplet
checking for a BSD-compatible install... configure: WARNING: Continuing even with errors mentioned immediately above this line.
configure: WARNING: Continuing even with errors mentioned immediately above this line.
>>> host-fakeroot 1.36 Building
awk: ./wrapawk: warning: regexp escape sequence `\#' is not a known regexp operator
./wrapawk:27: warning: regexp escape sequence `\#' is not a known regexp operator
awk: warning: regexp escape sequence `\#' is not a known regexp operator
warning: regexp escape sequence `\#' is not a known regexp operator
>>> host-flex 2.6.4 Building
parse.y:360:41: warning: '%s' directive output may be truncated [-Wformat-truncation=]
scan.c:8390:13: warning: conflicting types for built-in function 'malloc' [-Wbuiltin-declaration-mismatch]
make[1]: Entering directory '/workspace/buildroot/support/kconfig'
./util.c:86:26: warning: '%s' directive writing 10 or more bytes into a region of size between 1 and 4097 [-Wformat-overflow=]
>>> host-gcc-final 13.3.0 Building
checking sys/filio.h usability... Makefile:888: warning: overriding recipe for target 'all-multi'
checking sys/filio.h presence... Makefile:910: warning: overriding recipe for target 'all-multi'
>>> host-systemd 256.7 Building
../output/foo_defconfig/build/host-systemd-256.7/meson.build:907: WARNING:
../output/bar_defconfig/build/host-systemd-256.7/meson.build:913: WARNING:
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
assert evidence["summary"] == {"known-upstream": 27, "owned": 0, "third-party": 0}
assert evidence["unique_fingerprints"] == 17
assert evidence["fingerprints"]["warning: POSIX Yacc does not support %define [-Wyacc]"] == 3
raw = {warning["raw_fingerprint"] for warning in evidence["warnings"]}
assert ".1-7: warning: POSIX Yacc does not support %define [-Wyacc]" in raw
assert evidence["fingerprints"]["libtool: install: warning: remember to run `libtool --finish $OUTPUT_DIR/per-package/host-gcc-final/host/libexec/gcc/aarch64-buildroot-linux-gnu/13.3.0'"] == 2
assert evidence["fingerprints"]["libtool: link: warning: `-version-info/-version-number' is ignored for convenience libraries"] == 2
assert evidence["fingerprints"]["configure: WARNING: Continuing even with errors mentioned immediately above this line."] == 2
assert evidence["fingerprints"]["host-fakeroot: ./wrapawk: warning: regexp escape sequence `\\#' is not a known regexp operator"] == 4
assert evidence["fingerprints"]["host-gcc-final: Makefile: warning: overriding recipe for target 'all-multi'"] == 2
assert evidence["fingerprints"]["host-systemd: $OUTPUT_DIR/build/host-systemd-256.7/meson.build: WARNING:"] == 2
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

cat > "${TMP_DIR}/revpi-posix-yacc-fragment.log" <<'LOG'
>>> glibc 2.40 Building
.1-7: warning: POSIX Yacc does not support %define [-Wyacc]
LOG

python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${PROJECT_ROOT}/ci/build-warning-policy.json" \
    --json-output "${TMP_DIR}/revpi-posix-yacc-fragment.json" \
    "${TMP_DIR}/revpi-posix-yacc-fragment.log" >/dev/null

python3 - "${TMP_DIR}/revpi-posix-yacc-fragment.json" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1], encoding="utf-8").read())
warning = evidence["warnings"][0]
assert warning["fingerprint"] == "glibc: warning: POSIX Yacc does not support %define [-Wyacc]"
assert warning["raw_fingerprint"] == "glibc: .1-7: warning: POSIX Yacc does not support %define [-Wyacc]"
assert evidence["fingerprints"] == {
    "glibc: warning: POSIX Yacc does not support %define [-Wyacc]": 1,
}
assert not evidence["policy_errors"]
PY

cat > "${TMP_DIR}/fragment-negative.log" <<'LOG'
>>> glibc 2.40 Building
.1-7: warning: unrelated parser warning requiring triage [-Wother]
LOG

if python3 "${PROJECT_ROOT}/scripts/ci/classify-build-warnings.py" \
    --policy "${PROJECT_ROOT}/ci/build-warning-policy.json" \
    "${TMP_DIR}/fragment-negative.log" >/dev/null 2>&1; then
    echo "ERROR: unrelated fragmented warning was incorrectly canonicalized into policy" >&2
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
