#!/usr/bin/env bash
#
# /data grows to fill the disk before it is formatted (ADR-048 DEC-24).
#
# systemd-repart grows the data partition with usr/lib/repart.d/50-data.conf
# before suderra-data.service formats it as LUKS2. repart matches an existing
# partition to a definition by GPT type UUID alone, so the partition has a type
# of its own: the version-5 UUID of a URL, which this test recomputes. The test
# also runs the real systemd-repart against a partition table laid out like the
# production image, on a disk larger than the image, and checks that only /data
# grows, that the backup GPT moves to the disk's end, that a second run changes
# nothing, and that a definition for the generic Linux type would have been
# matched to the first rootfs slot, which has no free space behind it, so that
# /data would not have grown at all (the negative control the dedicated type
# exists for).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

command -v systemd-repart > /dev/null 2>&1 || fail "systemd-repart is required (package systemd)"

python3 -I - "${ROOT}" "${WORK}" << 'PY'
import json
import re
import struct
import subprocess
import sys
import uuid
import zlib
from pathlib import Path

root = Path(sys.argv[1])
work = Path(sys.argv[2])
overlay = root / "board/suderra/common/rootfs-overlay"
errors: list[str] = []

# -- the type UUID is derived, and one value everywhere -----------------------------
derived = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Okan-wqm/suderra-os/gpt-partition-type/data"))
definition_text = (overlay / "usr/lib/repart.d/50-data.conf").read_text(encoding="utf-8")
declared = re.search(r"^Type=([0-9a-f-]+)$", definition_text, re.M)
if not declared or declared.group(1) != derived:
    errors.append(f"50-data.conf must have Type={derived}, the UUIDv5 of the data partition type URL")
if "Label=data" not in definition_text:
    errors.append("50-data.conf must label the partition data: /dev/disk/by-partlabel/data is how the OS finds it")
GENERIC = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
prod_layouts = [
    "board/suderra/aarch64-rpi4/genimage-prod.cfg",
    "board/suderra/aarch64-revpi-connect4/genimage-prod.cfg",
    "board/suderra/x86_64/genimage.cfg",
]
for layout in prod_layouts:
    text = (root / layout).read_text(encoding="utf-8")
    match = re.search(r"partition data \{\s*partition-type-uuid = \"([0-9A-Fa-f-]+)\"", text)
    if not match or match.group(1).lower() != derived:
        errors.append(f"{layout}: the data partition must have the type UUID {derived} (repart matches by type alone)")
    names = re.findall(r"^\s*partition ([a-z0-9-]+) \{", text, re.M)
    if names[-1:] != ["data"]:
        errors.append(f"{layout}: data must be the last partition, or repart has no free space behind it to grow into")
# Dev layouts keep the generic type: no repart definition exists on a dev image.
for layout in ("board/suderra/aarch64/genimage.cfg", "board/suderra/x86_64/genimage-qemu.cfg"):
    text = (root / layout).read_text(encoding="utf-8")
    if derived in text.lower():
        errors.append(f"{layout}: a dev layout must not use the production data type")

# -- post-build: production images grow /data, others carry no definition ---------------
post_build = (root / "board/suderra/common/post-build.sh").read_text(encoding="utf-8")
if not re.search(r'enable_unit systemd-repart\.service sysinit\.target\n\s*preset_enable systemd-repart\.service', post_build):
    errors.append("post-build.sh must enable systemd-repart.service on production images")
if 'rm -f "${TARGET_DIR}/usr/lib/repart.d/50-data.conf"' not in post_build:
    errors.append("post-build.sh must delete usr/lib/repart.d/50-data.conf from images that are not production device images")
config_in = (root / "Config.in").read_text(encoding="utf-8")
if "select BR2_PACKAGE_SYSTEMD_REPART if BR2_PACKAGE_SUDERRA_VARIANT_PROD" not in config_in:
    errors.append("Config.in must select systemd-repart for the production variant")
dropin = (overlay / "etc/systemd/system/systemd-repart.service.d/10-suderra.conf").read_text(encoding="utf-8")
if "Before=suderra-data.service" not in dropin:
    errors.append("systemd-repart must run before suderra-data.service: /data is grown before it is formatted")

# -- a partition table like the production image's ----------------------------------
SECTOR = 512
MIB = 1024 * 1024


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["systemd-repart", *args], capture_output=True, text=True, check=check)


def write_fixture(directory: Path, data_type: str) -> None:
    directory.mkdir()
    parts = [
        ("00-boot", "esp", "boot", 32),
        ("10-rootfs-a", GENERIC, "rootfs-a", 16),
        ("11-rootfs-a-verity", GENERIC, "rootfs-a-verity", 8),
        ("20-rootfs-b", GENERIC, "rootfs-b", 16),
        ("21-rootfs-b-verity", GENERIC, "rootfs-b-verity", 8),
        ("90-data", data_type, "data", 64),
    ]
    for filename, type_, label, size in parts:
        (directory / f"{filename}.conf").write_text(
            f"[Partition]\nType={type_}\nLabel={label}\nSizeMinBytes={size}M\nSizeMaxBytes={size}M\n",
            encoding="utf-8",
        )


def read_gpt(image: Path) -> dict:
    data = image.read_bytes()
    total_sectors = len(data) // SECTOR
    header = data[SECTOR : SECTOR + 92]
    if header[:8] != b"EFI PART":
        raise SystemExit(f"{image}: no GPT header")
    (_, _, header_size, crc, _, current, backup, first, last, _guid, entries_lba, count, entry_size, entries_crc) = struct.unpack(
        "<8sIIIIQQQQ16sQIII", header
    )
    crc_check = zlib.crc32(header[:16] + b"\0\0\0\0" + header[20:header_size]) & 0xFFFFFFFF
    entries = data[entries_lba * SECTOR : entries_lba * SECTOR + count * entry_size]
    partitions = []
    for index in range(count):
        entry = entries[index * entry_size : (index + 1) * entry_size]
        type_guid = uuid.UUID(bytes_le=entry[:16])
        if type_guid.int == 0:
            continue
        start, end = struct.unpack("<QQ", entry[32:48])
        name = entry[56:128].decode("utf-16-le").rstrip("\0")
        partitions.append({"name": name, "type": str(type_guid), "start": start, "end": end})
    backup_header = data[backup * SECTOR : backup * SECTOR + 92]
    return {
        "header_crc_ok": crc_check == crc,
        "entries_crc_ok": (zlib.crc32(entries) & 0xFFFFFFFF) == entries_crc,
        "last_usable": last,
        "backup_lba": backup,
        "total_sectors": total_sectors,
        "backup_header_ok": backup_header[:8] == b"EFI PART",
        "partitions": partitions,
    }


def make_disk(name: str, data_type: str) -> Path:
    fixture = work / f"{name}.fixture.d"
    write_fixture(fixture, data_type)
    image = work / f"{name}.img"
    # The image genimage produces: exactly the partitions, no room behind them.
    run("--dry-run=no", f"--definitions={fixture}", "--empty=create", "--size=auto", str(image))
    # The flashed device is larger than the image: the backup GPT sits in the middle of it.
    with image.open("r+b") as handle:
        handle.truncate(512 * MIB)
    return image


production = make_disk("production", derived)
before = read_gpt(production)
if before["backup_lba"] == before["total_sectors"] - 1:
    errors.append("the fixture does not model a device larger than its image: the backup GPT is already at the end")
definitions = overlay / "usr/lib/repart.d"
result = run("--dry-run=no", f"--definitions={definitions}", str(production), check=False)
if result.returncode != 0:
    errors.append(f"systemd-repart failed on a production-shaped disk ({result.returncode}): {result.stderr.strip()}")
after = read_gpt(production)
if not (after["header_crc_ok"] and after["entries_crc_ok"] and after["backup_header_ok"]):
    errors.append("the partition table is not valid after the growth")
if after["backup_lba"] != after["total_sectors"] - 1:
    errors.append("the backup GPT did not move to the end of the larger device")
by_name = {p["name"]: p for p in after["partitions"]}
old_by_name = {p["name"]: p for p in before["partitions"]}
data = by_name.get("data")
if data is None:
    errors.append("the data partition disappeared")
else:
    # repart aligns a partition's end to 4 KiB (8 sectors).
    if after["last_usable"] - data["end"] >= 8:
        errors.append(f"data ends at sector {data['end']}, the last usable sector is {after['last_usable']}: it did not grow to fill the disk")
    if data["start"] != old_by_name["data"]["start"]:
        errors.append("data moved: it must only grow, behind its own start")
for name, partition in old_by_name.items():
    if name != "data" and by_name.get(name) != partition:
        errors.append(f"{name} changed although only data may grow")
if set(by_name) != set(old_by_name):
    errors.append(f"partitions appeared or disappeared: {sorted(set(by_name) ^ set(old_by_name))}")
if production.stat().st_size != 512 * MIB:
    errors.append("repart changed the size of the device")

# A second run, every boot after the first, changes nothing.
snapshot = production.read_bytes()
run("--dry-run=no", f"--definitions={definitions}", str(production), check=False)
if production.read_bytes() != snapshot:
    errors.append("a second systemd-repart run changed the disk: every boot would rewrite the partition table")

# The negative control: the definition for the generic Linux type is matched
# to the first rootfs slot, which another partition follows, so nothing grows
# and /data keeps its size. This is why /data has a type of its own.
naive = work / "naive.d"
naive.mkdir()
(naive / "50-data.conf").write_text(f"[Partition]\nType={GENERIC.lower()}\nLabel=data\nSizeMinBytes=64M\n", encoding="utf-8")
control = make_disk("control", derived)
control_before = {p["name"]: p for p in read_gpt(control)["partitions"]}
run("--dry-run=no", f"--definitions={naive}", str(control), check=False)
control_after = {p["name"]: p for p in read_gpt(control)["partitions"]}
if control_after["data"] != control_before["data"]:
    errors.append("the negative control grew /data with a generic-type definition: the dedicated type proves nothing; this test is not testing what it claims")
if control_after["data"]["end"] != control_before["data"]["end"] or len(control_after) != len(control_before):
    errors.append("the negative control changed the partition table: a generic-type definition must leave /data alone")

if errors:
    print("\n".join(f"ERROR: {line}" for line in errors), file=sys.stderr)
    sys.exit(1)
print(f"data growth: {data['end'] - data['start'] + 1} sectors after, {old_by_name['data']['end'] - old_by_name['data']['start'] + 1} before")
PY

# Production defconfigs build with repart; the others do not.
resolve() {
    make -s -C "${ROOT}/buildroot" BR2_EXTERNAL="${ROOT}" O="$2" "$1" > "$2.log" 2>&1 ||
        fail "Buildroot could not resolve $1 (see $2.log)"
}
for defconfig in suderra_aarch64_rpi4_prod_ab suderra_aarch64_revpi4_prod_ab suderra_qemu_x86_64_prod_ab suderra_x86_64; do
    resolve "${defconfig}_defconfig" "${WORK}/r-${defconfig}"
    grep -qx 'BR2_PACKAGE_SYSTEMD_REPART=y' "${WORK}/r-${defconfig}/.config" ||
        fail "${defconfig}: a production image must build systemd-repart"
done
for defconfig in suderra_aarch64_rpi4 suderra_aarch64_revpi4 suderra_qemu_x86_64 suderra_aarch64; do
    resolve "${defconfig}_defconfig" "${WORK}/r-${defconfig}"
    if grep -q '^BR2_PACKAGE_SYSTEMD_REPART=y' "${WORK}/r-${defconfig}/.config"; then
        fail "${defconfig}: a dev image must not carry systemd-repart"
    fi
done

echo "data growth contract passed"
