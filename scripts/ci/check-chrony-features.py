#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""The chronyd an image ships can do NTS (ADR-048 DEC-7.1; EI-046, EI-052).

Buildroot's chrony package passes --without-gnutls unless gnutls is selected,
and chrony's own configure then drops NTS silently: the build succeeds and the
daemon reports "-NTS -SECHASH" in its feature string. Every `server ... nts`
line of etc/chrony.conf would then be refused when chronyd starts, on an image
whose configuration, units and documentation all say its time is
authenticated. Config.in selects gnutls for every image; this gate proves the
result in the file that ships.

chronyd embeds the feature string it prints for `chronyd --version`
(CHRONYD_FEATURES of config.h, for example "+CMDMON +NTP +REFCLOCK +RTC
+PRIVDROP -SCFILTER -SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG") in its
read-only data, so the binary of a cross-compiled target can be checked
without running it.

    check-chrony-features.py TARGET_DIR

exits 0 when /usr/sbin/chronyd of TARGET_DIR reports every feature it must
have, and 1, naming the cause, when it is missing, carries no feature string
or lacks one.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Features the image's time design depends on. NTS is the authenticated
# source of DEC-7.1, RTC is the `rtcsync` of the boards with an RTC (DEC-7.1,
# DEC-7.8), PRIVDROP is the chrony user the nftables egress rule matches
# (DEC-11.4) and the owner of /var/lib/chrony (DEC-4.2).
REQUIRED_FEATURES = ("+NTP", "+NTS", "+RTC", "+PRIVDROP", "+CMDMON")

CHRONYD = "usr/sbin/chronyd"

# The feature string starts with the first feature chrony lists and runs to
# the end of the string literal.
FEATURE_STRING = re.compile(rb"[+-]CMDMON[ -~]{0,200}")


def feature_strings(data: bytes) -> list[str]:
    """Every feature string literal in the binary."""
    found = []
    for match in FEATURE_STRING.finditer(data):
        text = match.group(0).decode("ascii")
        tokens = text.split(" ")
        # A feature string is made only of "+NAME"/"-NAME" tokens.
        if all(re.fullmatch(r"[+-][A-Z0-9]+", token) for token in tokens):
            found.append(text)
    return found


def check(target: Path) -> list[str]:
    """The reasons `target` ships a chronyd without NTS; empty when it has it."""
    binary = target / CHRONYD
    if not binary.is_file():
        return [f"{CHRONYD} is not in the target: select chrony (Config.in BR2_PACKAGE_SUDERRA_TIME_SYNC)"]
    strings = feature_strings(binary.read_bytes())
    if not strings:
        return [f"{CHRONYD} carries no chrony feature string, so what it was built with cannot be proven"]
    if len(set(strings)) != 1:
        return [f"{CHRONYD} carries different feature strings: {sorted(set(strings))}"]
    features = strings[0].split(" ")
    errors = []
    for required in REQUIRED_FEATURES:
        if required not in features:
            name = required[1:]
            hint = ""
            if name == "NTS":
                hint = (
                    " (chrony builds NTS only with gnutls, TLS 1.3 and AES-SIV: "
                    "Config.in must select BR2_PACKAGE_GNUTLS)"
                )
            errors.append(f"{CHRONYD} reports {strings[0]!r}, which lacks {required}{hint}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 2
    errors = check(Path(argv[1]))
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
