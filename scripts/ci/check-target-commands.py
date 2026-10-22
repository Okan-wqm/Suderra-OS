#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Every external command a root script runs must exist in the image (EI-078).

No defconfig selected e2fsprogs, so the first-boot /data provisioning died at
`mkfs.ext4` after the LUKS volume was already formatted and sealed. Nothing
connected what the scripts run to what the image ships. This tool does:

* `check` reads the shell scripts out of a Buildroot TARGET_DIR (the files the
  image actually ships), extracts every command word each one runs, and
  requires the set to equal what board/suderra/common/runtime-commands.json
  declares for that script, then resolves every command the image's variant,
  architecture and configuration require in the target's PATH. post-build.sh
  runs it for every defconfig, so a missing package fails the build.
* `extract` prints what it extracts from scripts (the debugging view).

The extraction is a small POSIX shell lexer and parser, not a regular
expression: it knows quoting, command substitutions, here-documents, `case`
patterns, function definitions, assignments, redirections and the commands
that run other commands (`command`, `exec`, `env`, `trap`, `eval`, `sh -c`,
...). It refuses what it does not understand (an unbalanced quote, a command
word that is built at run time) instead of guessing, so a script cannot hide a
dependency from it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Commands the shell itself provides. BusyBox ash (the image's /bin/sh) and
# dash implement every one of them as a builtin; a script must not depend on
# an external binary for them.
BUILTINS = frozenset(
    {
        ":",
        ".",
        "[",
        "break",
        "cd",
        "command",
        "continue",
        "echo",
        "eval",
        "exec",
        "exit",
        "export",
        "false",
        "getopts",
        "hash",
        "kill",
        "local",
        "printf",
        "pwd",
        "read",
        "readonly",
        "return",
        "set",
        "shift",
        "test",
        "times",
        "trap",
        "true",
        "type",
        "ulimit",
        "umask",
        "unset",
        "wait",
    }
)

# Words that begin a compound command and are followed by a command.
PREFIX_RESERVED = frozenset(
    {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "}"}
)
# Words that only end a compound command.
CLOSING_RESERVED = frozenset({"fi", "done", "esac"})
# Commands that run another command, which is then also a dependency.
WRAPPERS_WITH_OPTIONS = frozenset(
    {"nohup", "nice", "setsid", "env", "stdbuf", "ionice", "timeout"}
)
WRAPPERS_SKIPPING_ONE = frozenset({"timeout"})
SHELLS = frozenset({"sh", "ash", "bash", "dash"})
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
VARIABLE_ONLY = re.compile(
    r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$"
)
PARAMETER_DEFAULT = re.compile(r'^"?\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^$"}`]*)\}"?$')
IO_NUMBER = re.compile(r"^[0-9]+$")
SHELL_SHEBANG = re.compile(
    rb"^#![ \t]*(?:/usr)?/(?:s?bin|usr/bin)/(?:env[ \t]+)?(?:ba|da|a)?sh\b"
)

# systemd's compiled-in PATH for system services, and BusyBox's login PATH: a
# merged-/usr image (systemd forces it) has one set of directories.
DEFAULT_SEARCH_PATH = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


class ShellError(Exception):
    """The script uses a construct the extractor refuses to guess about."""


@dataclass
class Word:
    raw: str
    literal: str | None  # the word after quote removal; None when it expands
    line: int


@dataclass
class Token:
    kind: str  # WORD, OP, EOF
    text: str = ""
    word: Word | None = None
    line: int = 0


@dataclass
class Extraction:
    commands: dict[str, list[int]] = field(default_factory=dict)
    probes: dict[str, list[int]] = field(default_factory=dict)
    functions: set[str] = field(default_factory=set)
    assignments: dict[str, set[str]] = field(default_factory=dict)
    dynamic: list[tuple[int, str]] = field(default_factory=list)

    def add(self, table: dict[str, list[int]], name: str, line: int) -> None:
        table.setdefault(name, []).append(line)


class Lexer:
    """Tokens of one piece of shell text; command substitutions are returned
    attached to their word, here-document bodies are consumed in place."""

    def __init__(self, text: str, first_line: int = 1) -> None:
        self.text = text
        self.pos = 0
        self.line = first_line
        self.pending_heredocs: list[tuple[str, bool, bool]] = []
        self.substitutions: list[tuple[str, int]] = []  # (inner text, line)

    # -- low-level helpers -------------------------------------------------
    def peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < len(self.text) else ""

    def advance(self) -> str:
        char = self.text[self.pos]
        self.pos += 1
        if char == "\n":
            self.line += 1
        return char

    def fail(self, message: str) -> ShellError:
        return ShellError(f"line {self.line}: {message}")

    # -- command substitutions ---------------------------------------------
    def read_balanced_parens(self) -> str:
        """After `$(`: the text up to the matching `)`; quotes and nested
        parentheses are skipped, `case` patterns are not supported inside."""
        start = self.pos
        depth = 1
        while self.pos < len(self.text):
            char = self.peek()
            if char == "\\":
                self.advance()
                if self.pos < len(self.text):
                    self.advance()
                continue
            if char == "'":
                self.skip_single_quote()
                continue
            if char == '"':
                self.skip_double_quote()
                continue
            if char == "#" and self.is_comment_start(start):
                while self.pos < len(self.text) and self.peek() != "\n":
                    self.advance()
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    inner = self.text[start : self.pos]
                    self.advance()
                    return inner
            self.advance()
        raise self.fail("unterminated $(")

    def is_comment_start(self, start: int) -> bool:
        if self.pos == start:
            return True
        return self.text[self.pos - 1] in " \t\n;&|("

    def read_backticks(self) -> str:
        start = self.pos
        while self.pos < len(self.text):
            char = self.peek()
            if char == "\\":
                self.advance()
                if self.pos < len(self.text):
                    self.advance()
                continue
            if char == "`":
                inner = self.text[start : self.pos]
                self.advance()
                return inner
            self.advance()
        raise self.fail("unterminated backtick")

    def skip_single_quote(self) -> None:
        self.advance()
        while self.pos < len(self.text) and self.peek() != "'":
            self.advance()
        if self.pos >= len(self.text):
            raise self.fail("unterminated single quote")
        self.advance()

    def skip_double_quote(self) -> None:
        """Skip a double-quoted string, collecting its substitutions."""
        self.advance()
        while self.pos < len(self.text):
            char = self.peek()
            if char == "\\":
                self.advance()
                if self.pos < len(self.text):
                    self.advance()
                continue
            if char == '"':
                self.advance()
                return
            if char == "$" and self.peek(1) == "(":
                self.read_dollar()
                continue
            if char == "$" and self.peek(1) == "{":
                self.skip_braced()
                continue
            if char == "`":
                line = self.line
                self.advance()
                self.substitutions.append((self.read_backticks(), line))
                continue
            self.advance()
        raise self.fail("unterminated double quote")

    def skip_braced(self) -> None:
        """Skip `${...}`; substitutions inside are collected."""
        self.advance()
        self.advance()
        depth = 1
        while self.pos < len(self.text):
            char = self.peek()
            if char == "\\":
                self.advance()
                if self.pos < len(self.text):
                    self.advance()
                continue
            if char == "'":
                self.skip_single_quote()
                continue
            if char == '"':
                self.skip_double_quote()
                continue
            if char == "$" and self.peek(1) == "(":
                self.read_dollar()
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    self.advance()
                    return
            self.advance()
        raise self.fail("unterminated ${")

    def read_dollar(self) -> None:
        """At `$(`: arithmetic is skipped, a command substitution collected."""
        line = self.line
        self.advance()
        self.advance()
        if self.peek() == "(":
            # $(( ... )): arithmetic expansion
            self.advance()
            depth = 2
            while self.pos < len(self.text) and depth > 0:
                char = self.advance()
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
            if depth != 0:
                raise self.fail("unterminated $((")
            return
        self.substitutions.append((self.read_balanced_parens(), line))

    # -- words and operators ------------------------------------------------
    def skip_blanks_and_comments(self) -> None:
        while self.pos < len(self.text):
            char = self.peek()
            if char in " \t":
                self.advance()
            elif char == "\\" and self.peek(1) == "\n":
                self.advance()
                self.advance()
            elif char == "#":
                while self.pos < len(self.text) and self.peek() != "\n":
                    self.advance()
            else:
                break

    def read_word(self) -> Word:
        start = self.pos
        line = self.line
        literal: list[str] = []
        expands = False
        while self.pos < len(self.text):
            char = self.peek()
            if char in " \t\n;&|()<>":
                break
            if char == "\\":
                self.advance()
                if self.pos >= len(self.text):
                    break
                escaped = self.advance()
                if escaped != "\n":
                    literal.append(escaped)
                continue
            if char == "'":
                begin = self.pos + 1
                self.skip_single_quote()
                literal.append(self.text[begin : self.pos - 1])
                continue
            if char == '"':
                begin = self.pos + 1
                before = len(self.substitutions)
                self.skip_double_quote()
                inner = self.text[begin : self.pos - 1]
                if "$" in inner or "`" in inner or len(self.substitutions) != before:
                    expands = True
                literal.append(inner)
                continue
            if char == "$" and self.peek(1) == "(":
                expands = True
                self.read_dollar()
                continue
            if char == "$" and self.peek(1) == "{":
                expands = True
                self.skip_braced()
                continue
            if char == "$":
                expands = True
                literal.append(self.advance())
                continue
            if char == "`":
                expands = True
                self.advance()
                self.substitutions.append((self.read_backticks(), line))
                continue
            literal.append(self.advance())
        raw = self.text[start : self.pos]
        return Word(raw=raw, literal=None if expands else "".join(literal), line=line)

    def read_heredoc_bodies(self) -> None:
        for delimiter, quoted, strip_tabs in self.pending_heredocs:
            body_start = self.pos
            while True:
                if self.pos >= len(self.text):
                    raise self.fail(f"unterminated here-document {delimiter!r}")
                end = self.text.find("\n", self.pos)
                line_end = len(self.text) if end == -1 else end
                content = self.text[self.pos : line_end]
                compare = content.lstrip("\t") if strip_tabs else content
                if compare == delimiter:
                    body = self.text[body_start : self.pos]
                    self.pos = line_end
                    if self.pos < len(self.text):
                        self.advance()  # the newline after the delimiter
                    if not quoted:
                        self.collect_heredoc_substitutions(body)
                    break
                self.pos = line_end
                if self.pos < len(self.text):
                    self.advance()
        self.pending_heredocs = []

    def collect_heredoc_substitutions(self, body: str) -> None:
        """An unquoted here-document expands like a double-quoted string, but
        a quote character in it is plain text."""
        inner = Lexer(body, self.line)
        inner.scan_heredoc_expansions()
        self.substitutions.extend(inner.substitutions)

    def scan_heredoc_expansions(self) -> None:
        while self.pos < len(self.text):
            char = self.peek()
            if char == "\\":
                self.advance()
                if self.pos < len(self.text):
                    self.advance()
            elif char == "$" and self.peek(1) == "(":
                self.read_dollar()
            elif char == "$" and self.peek(1) == "{":
                self.skip_braced()
            elif char == "`":
                line = self.line
                self.advance()
                self.substitutions.append((self.read_backticks(), line))
            else:
                self.advance()

    def next_token(self) -> Token:
        self.skip_blanks_and_comments()
        if self.pos >= len(self.text):
            return Token("EOF", line=self.line)
        line = self.line
        char = self.peek()
        if char == "\n":
            self.advance()
            if self.pending_heredocs:
                self.read_heredoc_bodies()
            return Token("OP", "\n", line=line)
        if char in ";&|":
            two = self.text[self.pos : self.pos + 2]
            if two in (";;", "&&", "||", ";&"):
                self.advance()
                self.advance()
                return Token("OP", two, line=line)
            self.advance()
            return Token("OP", char, line=line)
        if char in "()":
            self.advance()
            return Token("OP", char, line=line)
        if char in "<>":
            return self.read_redirect(line)
        word = self.read_word()
        if (
            self.peek() in ("<", ">")
            and word.literal is not None
            and IO_NUMBER.match(word.literal)
        ):
            return self.read_redirect(line)
        return Token("WORD", word.literal or "", word, line)

    def read_redirect(self, line: int) -> Token:
        op = self.advance()
        if op == "<" and self.peek() == "<":
            self.advance()
            op = "<<"
            strip_tabs = False
            if self.peek() == "-":
                self.advance()
                strip_tabs = True
            self.skip_blanks_and_comments()
            target = self.read_word()
            if target.literal is None:
                raise self.fail("a here-document delimiter with an expansion")
            quoted = target.raw != target.literal
            self.pending_heredocs.append((target.literal, quoted, strip_tabs))
            return Token("REDIR", op, line=line)
        if self.peek() in "<>&|":
            op += self.advance()
        self.skip_blanks_and_comments()
        if self.pos < len(self.text) and self.peek() not in "\n;&|()":
            self.read_word()
        return Token("REDIR", op, line=line)


class Parser:
    """Walks the tokens of one text and records the commands it runs."""

    def __init__(self, extraction: Extraction) -> None:
        self.extraction = extraction

    def parse(self, text: str, first_line: int = 1) -> None:
        lexer = Lexer(text, first_line)
        self.parse_list(lexer, closers=frozenset())
        for inner, line in lexer.substitutions:
            self.parse(inner, line)

    def parse_list(self, lexer: Lexer, closers: frozenset[str]) -> str:
        words: list[Word] = []
        depth = 0
        while True:
            token = lexer.next_token()
            if token.kind == "WORD" and token.word is not None:
                words.append(token.word)
                if (
                    len(words) >= 3
                    and words[0].literal == "case"
                    and token.word.literal == "in"
                ):
                    self.parse_case(lexer)
                    words = []
                continue
            if token.kind == "REDIR":
                continue
            if token.kind == "EOF":
                self.finish(words)
                return "EOF"
            if token.text in ("\n", ";", "&", "&&", "||", "|"):
                self.finish(words)
                words = []
                continue
            if token.text == "(":
                if len(words) == 1 and words[0].literal is not None:
                    # name() { ... }: a function definition
                    closing = lexer.next_token()
                    if closing.kind != "OP" or closing.text != ")":
                        raise ShellError(
                            f"line {token.line}: expected ')' after a function name"
                        )
                    self.extraction.functions.add(words[0].literal)
                    words = []
                    continue
                self.finish(words)
                words = []
                depth += 1
                continue
            if token.text == ")":
                self.finish(words)
                words = []
                if depth > 0:
                    depth -= 1
                    continue
                if ")" in closers:
                    return ")"
                raise ShellError(f"line {token.line}: unbalanced ')'")
            if token.text in (";;", ";&"):
                self.finish(words)
                if token.text in closers:
                    return token.text
                raise ShellError(f"line {token.line}: {token.text!r} outside a case")

    def parse_case(self, lexer: Lexer) -> None:
        """After `case WORD in`: patterns and their command lists up to esac."""
        while True:
            patterns = 0
            while True:
                token = lexer.next_token()
                if token.kind == "EOF":
                    raise ShellError(f"line {lexer.line}: case without esac")
                if token.kind == "OP" and token.text == "\n":
                    continue
                if (
                    token.kind == "WORD"
                    and token.word is not None
                    and token.word.literal == "esac"
                    and patterns == 0
                ):
                    return
                if token.kind == "OP" and token.text == "(" and patterns == 0:
                    continue
                if token.kind == "WORD":
                    patterns += 1
                    continue
                if token.kind == "OP" and token.text == "|":
                    continue
                if token.kind == "OP" and token.text == ")":
                    break
                raise ShellError(
                    f"line {token.line}: unexpected {token.text!r} in a case pattern"
                )
            ended = self.parse_case_body(lexer)
            if ended == "esac":
                return

    def parse_case_body(self, lexer: Lexer) -> str:
        """Commands of one case branch; stops at `;;`, or at `esac`."""
        words: list[Word] = []
        depth = 0
        while True:
            token = lexer.next_token()
            if token.kind == "WORD" and token.word is not None:
                if not words and token.word.literal == "esac":
                    return "esac"
                words.append(token.word)
                if (
                    len(words) >= 3
                    and words[0].literal == "case"
                    and token.word.literal == "in"
                ):
                    self.parse_case(lexer)
                    words = []
                continue
            if token.kind == "REDIR":
                continue
            if token.kind == "EOF":
                raise ShellError(f"line {lexer.line}: case without esac")
            if token.text in ("\n", ";", "&", "&&", "||", "|"):
                self.finish(words)
                words = []
                continue
            if token.text == "(":
                if len(words) == 1 and words[0].literal is not None:
                    closing = lexer.next_token()
                    if closing.kind != "OP" or closing.text != ")":
                        raise ShellError(
                            f"line {token.line}: expected ')' after a function name"
                        )
                    self.extraction.functions.add(words[0].literal)
                    words = []
                    continue
                self.finish(words)
                words = []
                depth += 1
                continue
            if token.text == ")":
                self.finish(words)
                words = []
                if depth > 0:
                    depth -= 1
                    continue
                raise ShellError(f"line {token.line}: unbalanced ')' in a case branch")
            if token.text in (";;", ";&"):
                self.finish(words)
                return ";;"

    # -- simple commands ----------------------------------------------------
    def finish(self, words: list[Word]) -> None:
        index = 0
        while index < len(words) and words[index].literal in PREFIX_RESERVED:
            index += 1
        if index >= len(words):
            return
        first = words[index].literal
        if first in CLOSING_RESERVED:
            return
        if first in ("for", "select"):
            return  # the words after `in` are data
        while index < len(words) and ASSIGNMENT.match(words[index].raw):
            self.record_assignment(words[index])
            index += 1
        if index >= len(words):
            return
        self.emit(words[index], words[index + 1 :])

    def record_assignment(self, word: Word) -> None:
        name, _, value = word.raw.partition("=")
        values = self.extraction.assignments.setdefault(name, set())
        if word.literal is not None:
            values.add(word.literal.partition("=")[2])
            return
        default = PARAMETER_DEFAULT.match(value)
        if default:
            # NAME="${OTHER:-/usr/bin/tool}": the image depends on the default;
            # an override is the caller's own business.
            values.add(default.group(1))
            return
        values.add(f"\0{value}")

    def emit(self, command: Word, args: list[Word]) -> None:
        name = self.command_name(command)
        if name is None:
            return
        if name in BUILTINS:
            self.emit_builtin(name, command, args)
            return
        self.extraction.add(self.extraction.commands, name, command.line)
        if name in WRAPPERS_WITH_OPTIONS:
            self.emit_wrapped(name, args)
        elif name in SHELLS:
            self.emit_shell(args)

    def command_name(self, command: Word) -> str | None:
        if command.literal is not None:
            return command.literal
        match = VARIABLE_ONLY.match(command.raw.strip('"'))
        if match:
            variable = match.group(1) or match.group(2)
            return f"\0var:{variable}"
        self.extraction.dynamic.append((command.line, command.raw))
        return None

    def emit_builtin(self, name: str, command: Word, args: list[Word]) -> None:
        if name == "command":
            if args and args[0].literal in ("-v", "-V"):
                if len(args) > 1 and args[1].literal is not None:
                    self.extraction.add(
                        self.extraction.probes, args[1].literal, command.line
                    )
                return
            rest = [word for word in args if word.literal not in ("-p",)]
            if rest:
                self.emit(rest[0], rest[1:])
        elif name == "exec":
            if args:
                self.emit(args[0], args[1:])
        elif name == "trap":
            if args and args[0].literal not in (None, "", "-"):
                self.parse_code(args[0].literal, command.line)
        elif name == "eval":
            if all(word.literal is not None for word in args):
                self.parse_code(
                    " ".join(word.literal or "" for word in args), command.line
                )
            elif args:
                self.extraction.dynamic.append(
                    (command.line, "eval " + " ".join(w.raw for w in args))
                )

    def emit_wrapped(self, name: str, args: list[Word]) -> None:
        rest = list(args)
        skip_one = name in WRAPPERS_SKIPPING_ONE
        while rest:
            word = rest[0]
            if word.literal is not None and word.literal.startswith("-"):
                rest = rest[1:]
                continue
            if name == "env" and ASSIGNMENT.match(word.raw):
                rest = rest[1:]
                continue
            if skip_one:
                skip_one = False
                rest = rest[1:]
                continue
            break
        if rest:
            self.emit(rest[0], rest[1:])

    def emit_shell(self, args: list[Word]) -> None:
        for position, word in enumerate(args):
            if word.literal == "-c" and position + 1 < len(args):
                code = args[position + 1]
                if code.literal is None:
                    self.extraction.dynamic.append((code.line, "sh -c " + code.raw))
                else:
                    self.parse_code(code.literal, code.line)
                return

    def parse_code(self, code: str, line: int) -> None:
        self.parse(code, line)


def extract(text: str) -> Extraction:
    extraction = Extraction()
    Parser(extraction).parse(text)
    return extraction


def external_commands(
    extraction: Extraction,
) -> tuple[dict[str, list[int]], list[tuple[int, str]]]:
    """The commands that must exist on disk, and the command words the image
    cannot be checked for. Functions and builtins are gone; `"${VAR}"` words
    are replaced by the literal their variable holds."""
    result: dict[str, list[int]] = {}
    dynamic: list[tuple[int, str]] = list(extraction.dynamic)
    for name, lines in extraction.commands.items():
        if name.startswith("\0var:"):
            variable = name[len("\0var:") :]
            values = extraction.assignments.get(variable, set())
            literals = {value for value in values if not value.startswith("\0")}
            if len(literals) == 1 and len(literals) == len(values):
                resolved = next(iter(literals))
                if resolved in BUILTINS or resolved in extraction.functions:
                    continue
                result.setdefault(resolved, []).extend(lines)
            else:
                dynamic.extend((line, f"${{{variable}}}") for line in lines)
            continue
        if name in extraction.functions:
            continue
        result.setdefault(name, []).extend(lines)
    return result, sorted(dynamic)


def probed_commands(extraction: Extraction) -> dict[str, list[int]]:
    return {
        name: lines
        for name, lines in extraction.probes.items()
        if name not in BUILTINS and name not in extraction.functions
    }


# -- the image side ----------------------------------------------------------
def resolve_in_target(target: Path, path: str, depth: int = 0) -> Path | None:
    """Resolve an absolute image path inside `target` the way the image itself
    would, following absolute and relative symlinks relative to the image root."""
    if depth > 40:
        return None
    current = target
    parts = [part for part in path.split("/") if part]
    walked: list[str] = []
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            if walked:
                walked.pop()
            current = target.joinpath(*walked) if walked else target
            continue
        candidate = current / part
        if candidate.is_symlink():
            link = os.readlink(candidate)
            if link.startswith("/"):
                walked = []
                current = target
                parts = [p for p in link.split("/") if p] + parts
            else:
                parts = [p for p in link.split("/") if p] + parts
            continue
        if not candidate.exists():
            return None
        walked.append(part)
        current = candidate
    return current


def command_resolves(target: Path, command: str, search_path: tuple[str, ...]) -> bool:
    candidates = (
        [command]
        if "/" in command
        else [f"{directory}/{command}" for directory in search_path]
    )
    for candidate in candidates:
        resolved = resolve_in_target(target, candidate)
        if (
            resolved is not None
            and resolved.is_file()
            and resolved.stat().st_mode & stat.S_IXUSR
        ):
            return True
    return False


def config_symbols(path: Path | None) -> set[str]:
    if path is None:
        return set()
    return set(
        re.findall(r"^(BR2_[A-Za-z0-9_]+)=y$", path.read_text(encoding="utf-8"), re.M)
    )


def condition_holds(
    when: dict[str, str], variant: str, arch: str, symbols: set[str]
) -> bool:
    if "variant" in when and when["variant"] != variant:
        return False
    if "arch" in when and when["arch"] != arch:
        return False
    return not ("config" in when and when["config"] not in symbols)


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for script, entry in manifest["scripts"].items():
        for group in entry["groups"]:
            unknown = set(group.get("when", {})) - {"variant", "arch", "config"}
            if unknown:
                raise SystemExit(
                    f"{path}: {script}: unknown condition {sorted(unknown)}"
                )
    return manifest


def shell_script_paths(target: Path) -> list[str]:
    """Shell scripts of the image that carry a Suderra name: they are the code
    this OS owns, whichever package or overlay installed them."""
    found: list[str] = []
    for directory in (
        "usr/sbin",
        "usr/bin",
        "usr/libexec",
        "usr/lib/suderra",
        "usr/lib/rauc",
    ):
        base = target / directory
        if not base.is_dir():
            continue
        for item in sorted(base.rglob("*")):
            if not item.is_file() or item.is_symlink():
                continue
            if not item.name.startswith("suderra-") and directory != "usr/lib/suderra":
                continue
            with item.open("rb") as handle:
                if SHELL_SHEBANG.match(handle.read(80)):
                    found.append(item.relative_to(target).as_posix())
    return found


def check(
    target: Path,
    manifest_path: Path,
    variant: str,
    arch: str,
    config: Path | None,
) -> list[str]:
    manifest = load_manifest(manifest_path)
    search_path = tuple(manifest.get("search_path", DEFAULT_SEARCH_PATH))
    symbols = config_symbols(config)
    problems: list[str] = []
    shipped = shell_script_paths(target)

    for script in shipped:
        if script not in manifest["scripts"]:
            problems.append(
                f"{script}: a shell script of the image has no entry in {manifest_path.name}; "
                "declare the commands it runs"
            )

    for script, entry in sorted(manifest["scripts"].items()):
        script_path = target / script
        if not script_path.is_file():
            continue  # the script is not part of this image
        try:
            extraction = extract(script_path.read_text(encoding="utf-8"))
        except ShellError as error:
            problems.append(f"{script}: {error}")
            continue
        used, dynamic = external_commands(extraction)
        probed = probed_commands(extraction)
        allowed_dynamic = set(entry.get("allow_dynamic", {}))
        for line, word in dynamic:
            if word not in allowed_dynamic:
                problems.append(
                    f"{script}:{line}: the command word {word} is built at run time, so the "
                    f"image cannot be checked for it; name the command, or declare the word in "
                    f"allow_dynamic with the reason"
                )
        used_words = {word for _, word in dynamic}
        for word in sorted(allowed_dynamic - used_words):
            problems.append(
                f"{script}: {manifest_path.name} allows the dynamic command word {word}, "
                "which the script no longer uses"
            )
        declared: set[str] = set()
        required: dict[str, str] = {}
        for group in entry["groups"]:
            names = set(group["commands"])
            declared |= names
            if not condition_holds(group.get("when", {}), variant, arch, symbols):
                continue
            if group.get("optional", False):
                continue
            for name in names:
                required[name] = json.dumps(group.get("when", {}), sort_keys=True)
        for name in sorted(set(used) | set(probed)):
            if name not in declared:
                lines = ",".join(
                    str(n) for n in (used.get(name) or probed.get(name) or [])
                )
                problems.append(
                    f"{script}:{lines}: runs `{name}`, which {manifest_path.name} does not declare for this script"
                )
        for name in sorted(declared - set(used) - set(probed)):
            problems.append(
                f"{script}: {manifest_path.name} declares `{name}`, which the script no longer runs"
            )
        for name, when in sorted(required.items()):
            if not command_resolves(target, name, search_path):
                problems.append(
                    f"{script}: `{name}` (required when {when}) does not exist in this image's "
                    f"{':'.join(search_path)}; select the package that provides it"
                )
    return problems


def cmd_extract(args: argparse.Namespace) -> int:
    status = 0
    for script in args.scripts:
        text = Path(script).read_text(encoding="utf-8")
        try:
            extraction = extract(text)
        except ShellError as error:
            print(f"{script}: ERROR {error}", file=sys.stderr)
            status = 1
            continue
        used, dynamic = external_commands(extraction)
        print(f"{script}")
        for name in sorted(used):
            print(f"  run   {name}  (lines {','.join(str(n) for n in used[name])})")
        for name, lines in sorted(probed_commands(extraction).items()):
            print(f"  probe {name}  (lines {','.join(str(n) for n in lines)})")
        for line, word in dynamic:
            print(f"  dyn   {word}  (line {line})")
    return status


def cmd_check(args: argparse.Namespace) -> int:
    problems = check(
        Path(args.target),
        Path(args.manifest),
        args.variant,
        args.arch,
        Path(args.config) if args.config else None,
    )
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if problems:
        print(f"{len(problems)} command problem(s) in {args.target}", file=sys.stderr)
        return 1
    print(f"target commands ok ({args.variant}, {args.arch})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    extract_parser = sub.add_parser("extract", help="print the commands scripts run")
    extract_parser.add_argument("scripts", nargs="+")
    extract_parser.set_defaults(func=cmd_extract)
    check_parser = sub.add_parser("check", help="check a Buildroot target tree")
    check_parser.add_argument("--target", required=True)
    check_parser.add_argument("--manifest", required=True)
    check_parser.add_argument("--variant", choices=("dev", "prod"), required=True)
    check_parser.add_argument("--arch", choices=("x86_64", "aarch64"), required=True)
    check_parser.add_argument("--config", help="Buildroot .config of the image")
    check_parser.set_defaults(func=cmd_check)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
