#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Suderra OS contributors
# SPDX-License-Identifier: Apache-2.0
"""Kernel freshness of every image (EI-028): no pinned kernel falls far behind its series.

A defconfig that pins a kernel.org version (BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE)
takes its security fixes only when someone bumps the pin: the stable series
publishes roughly weekly and Buildroot's own list lags. The pin was once left
at 6.12.6 until the series was 108 releases ahead, and nothing noticed
(EI-028). This check compares each such pin with kernel.org's own list of the
maintained series (https://www.kernel.org/releases.json) and fails when

  * the pinned series is not in that list or is marked end-of-life,
  * the pin is further than MAX_RELEASES_BEHIND stable releases behind the
    latest release of its series, counted as the difference of the patch
    numbers (kernel.org numbers a series' releases consecutively), or
  * the pin is ahead of the latest release: the data or the pin is wrong.

Kernels built from a vendor tree (BR2_LINUX_KERNEL_CUSTOM_TARBALL: the
Raspberry Pi and KUNBUS trees, pinned by commit) have the vendor's version, not
a kernel.org release, so they are listed and not compared.

The list is fetched from kernel.org, so a CI run needs the network: the
scheduled workflow runs this weekly (.github/workflows/kernel-freshness.yml),
and the pull-request check proves the logic on fixed data
(tests/image-contracts/kernel-freshness-contract-test.sh).

Remedy for a failure: bump the version in the named defconfigs, add its
sha256 line to board/suderra/buildroot-hashes/linux/linux.hash (computed from
the downloaded tarball and compared with the signed
https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc), and run
scripts/ci/check-kernel-config.py static.

Exit status: 0 every pin is fresh, 1 a pin is stale or inconsistent, 2 the
release list could not be obtained or understood.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASES_URL = "https://www.kernel.org/releases.json"

# About one quarter at the series' usual cadence of a release every one to two
# weeks. An owner decision: a smaller number means a bump every few weeks.
MAX_RELEASES_BEHIND = 12

VERSION = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$")


class FreshnessError(Exception):
    """The release list or a defconfig cannot be understood: exit status 2."""


@dataclass(frozen=True)
class Release:
    version: str
    series: str
    patch: int
    moniker: str
    eol: bool


def _load_read_defconfig():
    spec = importlib.util.spec_from_file_location("check_kernel_config", Path(__file__).with_name("check-kernel-config.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_kernel_config"] = module
    spec.loader.exec_module(module)
    return module.read_defconfig


def parse_releases(text: str) -> dict[str, Release]:
    """The maintained series of kernel.org's releases.json: series -> its latest release."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise FreshnessError(f"the release list is not JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("releases"), list):
        raise FreshnessError("the release list has no 'releases' array")
    series: dict[str, Release] = {}
    for entry in document["releases"]:
        if not isinstance(entry, dict):
            raise FreshnessError(f"a release entry is not an object: {entry!r}")
        for key in ("moniker", "version", "iseol"):
            if key not in entry:
                raise FreshnessError(f"a release entry has no '{key}': {entry!r}")
        if entry["moniker"] not in ("stable", "longterm"):
            continue  # mainline and linux-next are not a series a product pins
        match = VERSION.match(str(entry["version"]))
        if not match:
            raise FreshnessError(f"{entry['moniker']} release {entry['version']!r} is not X.Y.Z")
        name = f"{match.group(1)}.{match.group(2)}"
        if name in series:
            raise FreshnessError(f"series {name} is listed twice")
        series[name] = Release(entry["version"], name, int(match.group(3)), entry["moniker"], bool(entry["iseol"]))
    if not series:
        raise FreshnessError("the release list names no stable or longterm series")
    return series


def fetch_releases(url: str) -> str:
    if not url.startswith("https://"):
        raise FreshnessError(f"the release list is read over https only, not {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as error:
        raise FreshnessError(f"cannot read {url}: {error}") from error


def check(root: Path, releases: dict[str, Release], max_behind: int) -> tuple[list[str], list[str]]:
    """Return (report lines, problems) for every defconfig that builds a kernel."""
    read_defconfig = _load_read_defconfig()
    report: list[str] = []
    problems: list[str] = []
    checked = 0
    for path in sorted((root / "configs").glob("*_defconfig")):
        values = read_defconfig(path)
        if values.get("BR2_LINUX_KERNEL") != "y":
            continue
        name = path.name
        if values.get("BR2_LINUX_KERNEL_CUSTOM_TARBALL") == "y":
            report.append(f"{name}: vendor tree pinned by commit, not compared with kernel.org")
            continue
        if values.get("BR2_LINUX_KERNEL_CUSTOM_VERSION") != "y":
            problems.append(f"{name}: the kernel must be a pinned custom version or a pinned tarball (check-kernel-config.py static says the same)")
            continue
        version = values.get("BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE", "").strip('"')
        match = VERSION.match(version)
        if not match:
            problems.append(f"{name}: BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE {version!r} is not X.Y.Z")
            continue
        checked += 1
        series = f"{match.group(1)}.{match.group(2)}"
        patch = int(match.group(3))
        latest = releases.get(series)
        if latest is None:
            problems.append(
                f"{name}: kernel {version} is of series {series}, which kernel.org no longer lists as maintained "
                f"(maintained: {', '.join(sorted(releases))}): move to a maintained longterm series"
            )
            continue
        behind = latest.patch - patch
        state = f"{name}: kernel {version}, latest of {series} is {latest.version} ({latest.moniker}), {behind} release(s) behind (limit {max_behind})"
        if latest.eol:
            problems.append(f"{state}: series {series} is end-of-life")
        elif behind < 0:
            problems.append(f"{state}: the pin is newer than the latest release kernel.org lists, so the version or the list is wrong")
        elif behind > max_behind:
            problems.append(f"{state}: too stale, bump the pin to {latest.version} or a later {series}.y")
        else:
            report.append(state)
    if checked == 0:
        problems.append("no defconfig pins a kernel.org kernel version: this check would prove nothing")
    return report, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--releases-file", type=Path, help="read releases.json from this file instead of kernel.org")
    parser.add_argument("--releases-url", default=RELEASES_URL)
    parser.add_argument("--max-behind", type=int, default=MAX_RELEASES_BEHIND)
    args = parser.parse_args()
    try:
        if args.releases_file is not None:
            text = args.releases_file.read_text(encoding="utf-8")
        else:
            text = fetch_releases(args.releases_url)
        releases = parse_releases(text)
        report, problems = check(args.root.resolve(), releases, args.max_behind)
    except (FreshnessError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for line in report:
        print(line)
    for line in problems:
        print(f"ERROR: {line}", file=sys.stderr)
    if problems:
        print(f"kernel freshness: {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print("kernel freshness passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
