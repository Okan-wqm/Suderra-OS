#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Every result a shell script of the image writes is one the contract accepts (ADR-048 DEC-27, EI-084).

Root's shell helpers (suderra-lockdown, suderra-data-unlock, suderra-time-state)
record their outcome with `suderra-installer result write --kind K --outcome O
--reason R`. The installer validates the document against the contract's result
schema and refuses an invalid one, so a reason the schema does not allow for the
kind records nothing: the technician-visible result of exactly the failure it
describes is missing, and the script's own reason strings were checked against
nothing. suderra-lockdown reported `state-corrupt` for an open technician path
that way (EI-084).

This checker holds the producers to the schema (contracts/suderra-edge/v1/
schemas/result.schema.json, the vendored copy of the one the cloud validates
with):

* the kind is a literal the schema knows, and not one that must name a statement
  (`result write` has no --subject, so the schema refuses those documents);
* an outcome `ok` carries no reason, any other outcome carries one;
* the reason is one of the kind's reasons, wherever it is written: as a literal
  argument of `result write`, or as the literal a caller passes to a shell
  function that forwards its argument to `result write` (`failed`, `alarm`,
  `alarm_once`, `record_result`), traced through the functions that forward to
  those in turn.

A reason that cannot be traced to a literal fails the check: a string nobody can
read is a string nobody can check.

    check-result-reasons.py [--root DIR] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = Path("contracts/suderra-edge/v1/schemas/result.schema.json")
SCAN_DIRS = (Path("board"), Path("package"))
MAX_BYTES = 1 << 20

FUNCTION_START = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{")
RESULT_WRITE = re.compile(r"\bresult\s+write\b(.*)")
POSITIONAL = re.compile(r"^\$(?:([1-9])|\{([1-9])\})$")
NAMED = re.compile(r"^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$")
LITERAL = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


@dataclass(frozen=True)
class Contract:
    kinds: frozenset[str]
    outcomes: frozenset[str]
    reasons: dict[str, frozenset[str]]
    subject_kinds: frozenset[str]


def load_contract(root: Path) -> Contract:
    schema = json.loads((root / SCHEMA).read_text(encoding="utf-8"))
    reasons: dict[str, frozenset[str]] = {}
    for branch in schema["allOf"]:
        kind = branch["if"]["properties"]["kind"]["const"]
        reasons[kind] = frozenset(branch["then"]["properties"]["reason"]["enum"])
    kinds = frozenset(schema["properties"]["kind"]["enum"])
    if kinds != frozenset(reasons):
        raise SystemExit(f"{SCHEMA}: kinds {sorted(kinds ^ frozenset(reasons))} have no reason enum")
    subject_kinds = frozenset(schema["if"]["properties"]["kind"]["enum"])
    return Contract(
        kinds=kinds,
        outcomes=frozenset(schema["properties"]["outcome"]["enum"]),
        reasons=reasons,
        subject_kinds=subject_kinds,
    )


@dataclass
class Forwarder:
    """A shell function that hands its arguments to `result write`."""

    kind: str
    reason_pos: int
    outcome_pos: int | None
    outcome: str | None


@dataclass
class Report:
    problems: list[str] = field(default_factory=list)
    # script -> kind -> set of reasons written
    reasons: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    sites: dict[str, int] = field(default_factory=dict)

    def problem(self, where: str, text: str) -> None:
        self.problems.append(f"{where}: {text}")

    def wrote(self, script: str, kind: str, reason: str | None) -> None:
        self.sites[script] = self.sites.get(script, 0) + 1
        entry = self.reasons.setdefault(script, {}).setdefault(kind, set())
        if reason:
            entry.add(reason)


@dataclass
class Line:
    number: int
    text: str


def logical_lines(text: str) -> list[Line]:
    """Source lines with continuations joined and comment lines dropped."""
    out: list[Line] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if raw.rstrip().endswith("\\"):
            pending.append(raw.rstrip()[:-1])
            continue
        joined = " ".join(part.strip() for part in [*pending, raw])
        pending = []
        if joined.strip().startswith("#") or not joined.strip():
            continue
        out.append(Line(start, raw if joined == raw.strip() else joined))
    if pending:
        out.append(Line(start, " ".join(part.strip() for part in pending)))
    return out


@dataclass
class Function:
    name: str
    lines: list[Line]


def split_functions(lines: list[Line]) -> tuple[list[Function], list[Line]]:
    """The functions of a script (closing brace in column 0) and its top-level lines."""
    functions: list[Function] = []
    top: list[Line] = []
    current: Function | None = None
    for line in lines:
        if current is None:
            match = FUNCTION_START.match(line.text)
            if match:
                current = Function(match.group(1), [])
                if line.text.rstrip().endswith("}"):
                    functions.append(current)
                    current = None
            else:
                top.append(line)
        elif line.text.rstrip() == "}":
            functions.append(current)
            current = None
        else:
            current.lines.append(line)
    if current is not None:
        functions.append(current)
    return functions, top


def command_args(rest: str) -> list[str] | None:
    """The words of a simple command's arguments, or None when they do not parse.

    The command ends at the first redirection, pipe or list operator outside quotes
    (a `;` inside a quoted detail text does not end it).
    """
    lexer = shlex.shlex(rest, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    words: list[str] = []
    try:
        for token in lexer:
            if all(ch in lexer.punctuation_chars for ch in token):
                if token.startswith(">") and words and re.fullmatch(r"[0-9]", words[-1]):
                    words.pop()  # the file descriptor of `2>`
                break
            words.append(token)
    except ValueError:
        return None
    return words


def positional(word: str) -> int | None:
    match = POSITIONAL.match(word)
    return int(match.group(1) or match.group(2)) if match else None


def resolve_position(word: str, function: Function | None) -> int | None:
    """The positional parameter a word stands for: `$2`, or a local assigned from one."""
    pos = positional(word)
    if pos is not None:
        return pos
    named = NAMED.match(word)
    if named is None or function is None:
        return None
    name = named.group(1) or named.group(2)
    assign = re.compile(r'^\s*(?:local\s+)?' + re.escape(name) + r'="?\$\{?([1-9])\}?"?\s*$')
    for line in function.lines:
        found = assign.match(line.text)
        if found:
            return int(found.group(1))
    return None


def parse_invocation(words: list[str]) -> tuple[dict[str, str] | None, str | None]:
    options: dict[str, str] = {}
    it = iter(words)
    for word in it:
        if word in ("--kind", "--outcome", "--reason", "--detail"):
            value = next(it, None)
            if value is None:
                return None, f"{word} has no value"
            options[word[2:]] = value
        else:
            return None, f"unknown argument {word!r} (the schema's other members are not writable from a script)"
    return options, None


def check_reason(
    report: Report, where: str, contract: Contract, kind: str, outcome: str | None, reason: str | None
) -> None:
    if outcome == "ok" and reason:
        report.problem(where, f"outcome ok carries the reason {reason!r}: the schema forbids a reason on an ok result")
    if outcome in contract.outcomes - {"ok"} and not reason:
        report.problem(where, f"outcome {outcome} carries no reason: the schema requires one")
    if reason and reason not in contract.reasons[kind]:
        allowed = ", ".join(sorted(contract.reasons[kind]))
        report.problem(
            where,
            f"reason {reason!r} is not allowed for a {kind!r} result, so `result write` refuses it and nothing is "
            f"recorded; the schema allows: {allowed}",
        )


def scan_script(report: Report, contract: Contract, root: Path, path: Path) -> None:
    rel = path.relative_to(root).as_posix()
    functions, top = split_functions(logical_lines(path.read_text(encoding="utf-8", errors="replace")))
    contexts: list[tuple[Function | None, list[Line]]] = [(None, top), *[(f, f.lines) for f in functions]]
    forwarders: dict[str, Forwarder] = {}

    # 1. Direct invocations of `result write`.
    for function, lines in contexts:
        for line in lines:
            where = f"{rel}:{line.number}"
            match = RESULT_WRITE.search(line.text)
            if match is None:
                continue
            words = command_args(match.group(1))
            if words is None:
                report.problem(where, "the arguments of `result write` cannot be read")
                continue
            options, error = parse_invocation(words)
            if options is None:
                report.problem(where, error or "unreadable `result write`")
                continue
            kind = options.get("kind")
            if kind is None or kind.startswith("$"):
                report.problem(where, "the result kind is not a literal")
                continue
            if kind not in contract.kinds:
                report.problem(where, f"unknown result kind {kind!r}")
                continue
            if kind in contract.subject_kinds:
                report.problem(
                    where, f"a {kind!r} result must name the statement it concludes, and `result write` cannot"
                )
                continue
            outcome_word = options.get("outcome")
            if outcome_word is None:
                report.problem(where, "`result write` has no --outcome")
                continue
            reason_word = options.get("reason")
            outcome_pos = resolve_position(outcome_word, function)
            outcome = None if outcome_pos is not None else outcome_word
            if outcome is not None and outcome not in contract.outcomes:
                report.problem(where, f"unknown outcome {outcome!r}")
                continue
            if reason_word is None:
                if outcome_pos is None:
                    check_reason(report, where, contract, kind, outcome, None)
                report.wrote(rel, kind, None)
                continue
            reason_pos = resolve_position(reason_word, function)
            if reason_pos is not None and function is not None:
                forwarders[function.name] = Forwarder(kind, reason_pos, outcome_pos, outcome)
            elif LITERAL.match(reason_word):
                check_reason(report, where, contract, kind, outcome, reason_word)
                report.wrote(rel, kind, reason_word)
            else:
                report.problem(where, f"the reason {reason_word!r} cannot be traced to a literal")

    # 2. Functions that forward their arguments to a forwarder, until nothing changes.
    changed = True
    while changed:
        changed = False
        for function in functions:
            if function.name in forwarders:
                continue
            for line in function.lines:
                for name, fwd in list(forwarders.items()):
                    for call in calls_of(name, line.text):
                        reason_word = call[fwd.reason_pos - 1] if len(call) >= fwd.reason_pos else None
                        pos = resolve_position(reason_word, function) if reason_word else None
                        if pos is not None:
                            outcome_pos = None
                            outcome = fwd.outcome
                            if fwd.outcome_pos is not None and len(call) >= fwd.outcome_pos:
                                outcome_word = call[fwd.outcome_pos - 1]
                                outcome_pos = resolve_position(outcome_word, function)
                                outcome = None if outcome_pos is not None else outcome_word
                            forwarders[function.name] = Forwarder(fwd.kind, pos, outcome_pos, outcome)
                            changed = True

    # 3. Every call of a forwarder names a literal reason the kind allows.
    for function, lines in contexts:
        for line in lines:
            where = f"{rel}:{line.number}"
            for name, fwd in forwarders.items():
                if function is not None and function.name == name:
                    continue
                for call in calls_of(name, line.text):
                    reason_word = call[fwd.reason_pos - 1] if len(call) >= fwd.reason_pos else ""
                    outcome = fwd.outcome
                    if fwd.outcome_pos is not None:
                        outcome = call[fwd.outcome_pos - 1] if len(call) >= fwd.outcome_pos else None
                    if reason_word and (positional(reason_word) is not None) and function is not None:
                        if function.name in forwarders:
                            continue  # traced through the caller's own call sites
                    if reason_word == "" and outcome == "ok":
                        report.wrote(rel, fwd.kind, None)
                        check_reason(report, where, contract, fwd.kind, outcome, None)
                    elif LITERAL.match(reason_word or ""):
                        check_reason(report, where, contract, fwd.kind, outcome, reason_word)
                        report.wrote(rel, fwd.kind, reason_word)
                    else:
                        report.problem(
                            where, f"the reason passed to {name} ({reason_word!r}) cannot be traced to a literal"
                        )
    # A forwarder nobody calls is a producer the checker has no site to hold to the schema.
    for name in forwarders:
        called = any(
            calls_of(name, line.text)
            for function, lines in contexts
            for line in lines
            if function is None or function.name != name
        )
        if not called:
            report.problem(rel, f"function {name} forwards a reason to `result write` and nothing calls it")


def calls_of(name: str, text: str) -> list[list[str]]:
    """The argument words of every call of `name` at command position on a line."""
    out: list[list[str]] = []
    pattern = re.compile(r"(?:^\s*|[;&|(]\s*|\b(?:then|do|else)\s+|!\s+)" + re.escape(name) + r"(?=\s|$)(.*)")
    for match in pattern.finditer(text):
        words = command_args(match.group(1))
        if words is not None:
            out.append(words)
    return out


def text_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for directory in SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
                continue
            try:
                head = path.read_bytes()
            except OSError:
                continue
            if b"result write" in head and b"\0" not in head:
                found.append(path)
    return found


def check(root: Path) -> Report:
    contract = load_contract(root)
    report = Report()
    for path in text_files(root):
        scan_script(report, contract, root, path)
    if not report.sites:
        report.problem(
            "scan", "no script of the image writes a result: the checker found nothing to hold to the schema"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true", help="print what every script writes")
    args = parser.parse_args()
    report = check(args.root.resolve())
    if args.json:
        print(
            json.dumps(
                {
                    script: {"sites": report.sites[script], "kinds": {k: sorted(v) for k, v in kinds.items()}}
                    for script, kinds in sorted(report.reasons.items())
                },
                indent=2,
                sort_keys=True,
            )
        )
    for problem in report.problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    return 1 if report.problems else 0


if __name__ == "__main__":
    sys.exit(main())
