#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Check a suderra-agent.service against the Suderra edge contract.

The rules live in contracts/suderra-edge/v1/unit-directives.json (ADR-048
DEC-1.8, DEC-1.9, DEC-25) and nowhere else: this checker implements its
parsing rules (list_keys, ordered_keys, empty_value_keys, reset_rule) and its
exact / required / present / allowed / forbidden / board_dropins sections,
and reports violations as <category>:<Section>.<Key> exactly as the contract
names them. The contract's golden unit fixtures (fixtures/index.json
"units") pin the expected verdict and violation set of each fixture, so
`--fixtures` proves this implementation agrees with the contract before the
image's own unit is judged by it.

    check-unit-directives.py --contract unit-directives.json --profile suderra-os \
        --unit suderra-agent.service [--board revpi-connect4 --dropin 10-board-revpi-connect4.conf]
    check-unit-directives.py --contract unit-directives.json --fixtures fixtures/index.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Parsed:
    """Accumulated values of one unit file (or one drop-in)."""

    values: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    # Keys that appeared at all (an empty assignment counts).
    seen: set[tuple[str, str]] = field(default_factory=set)
    # Keys reset by an empty assignment (empty_value_keys excepted).
    reset: set[tuple[str, str]] = field(default_factory=set)
    # Keys with at least one empty assignment, including empty_value_keys.
    empty_assigned: set[tuple[str, str]] = field(default_factory=set)


def logical_lines(text: str) -> list[str]:
    """Unit-file lines with comments dropped and backslash continuations joined."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not pending and (not stripped or stripped[0] in "#;"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append(pending + stripped)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def parse(text: str, parsing: dict, into: Parsed | None = None) -> Parsed:
    """Parses `text` by the contract's parsing rules, on top of `into`."""
    list_keys = set(parsing["list_keys"])
    empty_value_keys = set(parsing["empty_value_keys"])
    out = into if into is not None else Parsed()
    section = None
    for line in logical_lines(text):
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section is None or "=" not in line:
            raise ValueError(f"not a unit-file assignment: {line!r}")
        key, value = line.split("=", 1)
        name = (section, key.strip())
        value = value.strip()
        out.seen.add(name)
        if value == "":
            out.empty_assigned.add(name)
            out.values[name] = []
            if name[1] not in empty_value_keys:
                out.reset.add(name)
            continue
        added = value.split() if name[1] in list_keys else [value]
        out.values.setdefault(name, []).extend(added)
    return out


def same(key: str, actual: list[str], expected: list[str], ordered: set[str]) -> bool:
    if key in ordered:
        return actual == expected
    return set(actual) == set(expected)


def rule_applies(rule: dict, profile: str) -> bool:
    return profile in rule.get("profiles", [profile])


def check(
    contract: dict,
    profile: str,
    unit_text: str,
    board: str | None = None,
    dropin_text: str | None = None,
) -> set[str]:
    """Returns the violation set of a unit (and its board drop-in)."""
    parsing = contract["parsing"]
    ordered = set(parsing["ordered_keys"])
    prof = contract["profiles"][profile]
    violations: set[str] = set()

    base = parse(unit_text, parsing)
    effective = parse(unit_text, parsing)

    exact: dict[tuple[str, str], list[str]] = {}
    for section, keys in contract["exact"].items():
        for key, values in keys.items():
            exact[(section, key)] = values
    for section, keys in prof["exact"].items():
        for key, values in keys.items():
            exact[(section, key)] = values
    required = {
        (section, key): values
        for section, keys in contract["required"].items()
        for key, values in keys.items()
    }
    present = {
        (section, key) for section, keys in contract["present"].items() for key in keys
    }
    allowed = {
        (section, key) for section, keys in contract["allowed"].items() for key in keys
    }
    named = set(exact) | set(required) | present

    board_keys: dict[tuple[str, str], list[str]] = {}
    if dropin_text is not None:
        if board is None:
            raise ValueError("a drop-in needs its board profile")
        listed = prof.get("board_dropins", {}).get("boards", {}).get(board)
        if listed is None:
            raise ValueError(f"profile {profile} has no drop-in for board {board}")
        board_keys = {("Service", key): values for key, values in listed.items()}
        dropin = parse(dropin_text, parsing)
        parse(dropin_text, parsing, into=effective)
        for name in dropin.seen:
            if name not in board_keys:
                violations.add(f"dropin:{name[0]}.{name[1]}")
        for name in dropin.empty_assigned:
            violations.add(f"reset:{name[0]}.{name[1]}")
        for name, listed_values in board_keys.items():
            # The drop-in adds to whatever the base unit holds; the base's
            # own deviation from the profile is an exact violation of the
            # base, not of the drop-in.
            expected = list(base.values.get(name, [])) + list(listed_values)
            if not same(name[1], effective.values.get(name, []), expected, ordered):
                violations.add(f"dropin:{name[0]}.{name[1]}")

    # Keys outside the allowlist; a key-level forbidden rule reports them as
    # forbidden instead.
    key_level_forbidden = {
        (rule["section"], rule["key"])
        for rule in contract["forbidden"]
        if "value_pattern" not in rule and rule_applies(rule, profile)
    }
    for name in base.seen:
        if name in named or name in allowed or name in board_keys:
            continue
        if name in key_level_forbidden:
            continue
        violations.add(f"unknown:{name[0]}.{name[1]}")

    for name in base.reset & named:
        violations.add(f"reset:{name[0]}.{name[1]}")

    for name, values in exact.items():
        if not same(name[1], base.values.get(name, []), values, ordered):
            violations.add(f"exact:{name[0]}.{name[1]}")
        if name in present and values == [] and name not in base.empty_assigned:
            # exact [] together with present means an explicit empty
            # assignment, which is the value itself (empty_value_keys).
            violations.add(f"exact:{name[0]}.{name[1]}")
    for name, values in required.items():
        if not set(values) <= set(base.values.get(name, [])):
            violations.add(f"required:{name[0]}.{name[1]}")
    for name in present:
        if name not in base.seen:
            violations.add(f"present:{name[0]}.{name[1]}")

    for rule in contract["forbidden"]:
        if not rule_applies(rule, profile):
            continue
        name = (rule["section"], rule["key"])
        if name not in effective.seen:
            continue
        pattern = rule.get("value_pattern")
        if pattern is None:
            violations.add(f"forbidden:{name[0]}.{name[1]}")
            continue
        if any(re.search(pattern, v) for v in effective.values.get(name, [])):
            violations.add(f"forbidden:{name[0]}.{name[1]}")
    return violations


def run_fixtures(contract: dict, index_path: Path) -> int:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    base = index_path.parent
    failures = 0
    for entry in index["units"]:
        unit = (base / entry["unit"]).read_text(encoding="utf-8")
        dropin = (
            (base / entry["dropin"]).read_text(encoding="utf-8") if entry["dropin"] else None
        )
        got = check(contract, entry["profile"], unit, entry["board_profile"], dropin)
        want = set(entry.get("violations", []))
        verdict = "accept" if not got else "reject"
        if verdict != entry["expect"] or got != want:
            failures += 1
            print(
                f"FIXTURE MISMATCH {entry['unit']} + {entry['dropin']}: "
                f"expected {entry['expect']} {sorted(want)}, got {verdict} {sorted(got)}",
                file=sys.stderr,
            )
    print(f"unit fixtures: {len(index['units']) - failures}/{len(index['units'])} agree")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--profile")
    parser.add_argument("--unit", type=Path)
    parser.add_argument("--board")
    parser.add_argument("--dropin", type=Path)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    if args.fixtures:
        return run_fixtures(contract, args.fixtures)
    if not args.profile or not args.unit:
        parser.error("--profile and --unit are required without --fixtures")
    dropin = args.dropin.read_text(encoding="utf-8") if args.dropin else None
    violations = check(
        contract, args.profile, args.unit.read_text(encoding="utf-8"), args.board, dropin
    )
    for v in sorted(violations):
        print(f"VIOLATION {v}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
