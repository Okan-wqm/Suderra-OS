#!/usr/bin/env bash
#
# Every external command a root script runs exists in the image (EI-078).
#
# No defconfig selected e2fsprogs, so the first-boot /data provisioning died at
# mkfs.ext4 after the LUKS volume was already formatted and sealed. Two things
# now keep that from happening again, and this test proves both work:
#
# 1. Config.in selects e2fsprogs through an option nobody can switch off: the
#    Buildroot-resolved .config of every defconfig has BR2_PACKAGE_E2FSPROGS=y,
#    and the same resolution of a tree without the select does not.
# 2. scripts/ci/check-target-commands.py, which post-build.sh runs on every
#    image, extracts the commands the shipped scripts run and checks them
#    against board/suderra/common/runtime-commands.json and against the target.
#    Its shell parser is tested on the constructs the scripts use; the gate is
#    tested on synthetic targets that each break it one way.
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

for tool in python3 make gcc; do
    command -v "${tool}" > /dev/null 2>&1 || fail "${tool} is required"
done
[ -f "${ROOT}/buildroot/Config.in" ] || fail "the buildroot submodule is not checked out"

python3 -B -m py_compile "${ROOT}/scripts/ci/check-target-commands.py"

# --- the parser and the gate ---------------------------------------------------
python3 -I - "${ROOT}" "${WORK}" << 'PY'
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
work = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("ctc", root / "scripts/ci/check-target-commands.py")
ctc = importlib.util.module_from_spec(spec)
sys.modules["ctc"] = ctc
spec.loader.exec_module(ctc)

failures: list[str] = []


def expect(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


# -- 1. the parser ---------------------------------------------------------------
def commands_of(text: str):
    extraction = ctc.extract(text)
    used, dynamic = ctc.external_commands(extraction)
    return set(used), set(ctc.probed_commands(extraction)), [word for _, word in dynamic]


SNIPPETS = [
    ("quoted words and comments are not commands", 'echo "mkfs.ext4 is not run"  # rm -rf /\nls #rm -rf', {"ls"}, set(), []),
    ("negated condition", 'if ! cryptsetup luksFormat --type luks2 "$d"; then rm -f "$k"; fi', {"cryptsetup", "rm"}, set(), []),
    ("substitution and pipeline", 'x="$(blkid -s TYPE "$d" | head -n 1)"', {"blkid", "head"}, set(), []),
    ("quoted here-document is data", "cat > \"$f\" <<'EOF'\n$(rm -rf /)\nEOF\nsync", {"cat", "sync"}, set(), []),
    ("unquoted here-document expands", "cat <<EOF\n$(date)\nEOF", {"cat", "date"}, set(), []),
    ("case patterns", 'case "$1" in\n  a|b) mount -o ro x y ;;\n  *[!0-9]*) umount z ;;\nesac\nsync', {"mount", "umount", "sync"}, set(), []),
    ("case in one line", 'case $x in a) rm f;; *) mkdir d;; esac', {"rm", "mkdir"}, set(), []),
    ("functions are not external", "f() { rm x; }\nf", {"rm"}, set(), []),
    ("a probe is not a run", 'command -v tool > /dev/null 2>&1 || exit 1', set(), {"tool"}, []),
    ("command runs its argument", "command mount x y", {"mount"}, set(), []),
    ("exec", "exec dropbear -F", {"dropbear"}, set(), []),
    ("wrappers", "env A=1 nohup chrony x", {"env", "nohup", "chrony"}, set(), []),
    ("timeout skips its duration", "timeout 5 udevadm settle", {"timeout", "udevadm"}, set(), []),
    ("trap handlers are code", "trap 'rm -f \"${k}\"' EXIT", {"rm"}, set(), []),
    ("eval", 'eval "mount x y"', {"mount"}, set(), []),
    ("sh -c", "sh -c 'dd if=/dev/zero of=/x'", {"sh", "dd"}, set(), []),
    ("assignment prefix", 'V=1 mkfs.ext4 -q "$d"', {"mkfs.ext4"}, set(), []),
    ("control operators", "a && b || c | d; e &", {"a", "b", "c", "d", "e"}, set(), []),
    ("redirections are not commands", "cmd >out 2>&1 <in", {"cmd"}, set(), []),
    ("for list is data", 'for x in a b c; do echo "$x"; done', set(), set(), []),
    ("builtins", "while read -r l; do printf '%s\\n' \"$l\"; done < file", set(), set(), []),
    ("arithmetic", "x=$(( 1 + 2 ))", set(), set(), []),
    ("line continuation", 'systemd-cryptenroll "$d" \\\n  --wipe-slot=password', {"systemd-cryptenroll"}, set(), []),
    ("subshell", "( cd /x && make )", {"make"}, set(), []),
    ("brace group", "{ rm x; } > /dev/null", {"rm"}, set(), []),
    ("backticks", "x=`uname -r`", {"uname"}, set(), []),
    ("a substitution as the command word is dynamic", "`pick`", {"pick"}, set(), ["`pick`"]),
    ("test with a path", "if [ -x /usr/bin/rauc ]; then :; fi", set(), set(), []),
    ("quoted command word", '"mkfs.ext4" -q x', {"mkfs.ext4"}, set(), []),
    ("substitution in double quotes", 'echo "$(mount | grep x)"', {"mount", "grep"}, set(), []),
    ("substitution in a default", 'x="${y:-$(cmd)}"', {"cmd"}, set(), []),
    ("until", "until cmd; do :; done", {"cmd"}, set(), []),
    ("unresolved variable command word", '"${tool}" arg', set(), set(), ['${tool}']),
    ("variable command word", 'T=/usr/bin/foo\n"${T}" x', {"/usr/bin/foo"}, set(), []),
    ("variable default", 'T="${X:-/usr/bin/bar}"\n"$T" run', {"/usr/bin/bar"}, set(), []),
    ("a variable assigned twice cannot be resolved", 'T=/a\nT=/b\n"$T" x', set(), set(), ['${T}']),
    ("function defined after the call", "g\ng() { rm x; }", {"rm"}, set(), []),
    ("elif and else", "if a; then b; elif c; then d; else e; fi", {"a", "b", "c", "d", "e"}, set(), []),
]
for description, text, run, probe, dynamic in SNIPPETS:
    try:
        got_run, got_probe, got_dynamic = commands_of(text)
    except ctc.ShellError as error:
        failures.append(f"parser: {description}: refused ({error})")
        continue
    expect(got_run == run, f"parser: {description}: ran {sorted(got_run)}, expected {sorted(run)}")
    expect(got_probe == probe, f"parser: {description}: probed {sorted(got_probe)}, expected {sorted(probe)}")
    expect(got_dynamic == dynamic, f"parser: {description}: dynamic {got_dynamic}, expected {dynamic}")

for description, text in [
    ("an unterminated double quote", 'echo "abc'),
    ("an unterminated single quote", "echo 'abc"),
    ("an unterminated substitution", "x=$(cmd"),
    ("an unterminated here-document", "cat <<EOF\nabc"),
    ("an unbalanced parenthesis", "cmd )"),
    ("a case without esac", "case x in a) rm f ;;"),
]:
    try:
        commands_of(text)
        failures.append(f"parser: {description}: accepted, it must be refused")
    except ctc.ShellError:
        pass

# -- 2. the real scripts parse and the manifest covers every shipped script ------------
manifest_path = root / "board/suderra/common/runtime-commands.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
expect(manifest["scripts"], "the manifest declares no script")
sources = {entry["source"] for entry in manifest["scripts"].values()}
for script, entry in manifest["scripts"].items():
    source = root / entry["source"]
    expect(source.is_file(), f"manifest: {script}: source {entry['source']} does not exist")
overlay = root / "board/suderra/common/rootfs-overlay/usr/sbin"
for item in sorted(overlay.iterdir()):
    relative = item.relative_to(root).as_posix()
    expect(relative in sources, f"manifest: the overlay script {relative} is not declared")
for package_script in sorted((root / "package").glob("*/suderra-*")):
    if package_script.suffix == ".py" or package_script.suffix in (".service", ".mk", ".hash"):
        continue
    first = package_script.read_bytes()[:80]
    if ctc.SHELL_SHEBANG.match(first):
        relative = package_script.relative_to(root).as_posix()
        expect(relative in sources, f"manifest: the package script {relative} is not declared")

# -- 3. the gate on synthetic targets ----------------------------------------------------
ALL_CONFIG = (
    "BR2_PACKAGE_SUDERRA_OS_INSTALLER=y\nBR2_PACKAGE_RAUC=y\nBR2_PACKAGE_SUDERRA_OTA=y\n"
)


# Device images do not ship the USB self-installer (post-build.sh deletes it).
DEVICE_IMAGE = frozenset({"usr/sbin/suderra-os-install"})
ELF = b"\x7fELF\x02\x01\x01\x00"


def make_target(
    destination: Path,
    skip: set[str] = frozenset(),
    drop: frozenset[str] = DEVICE_IMAGE,
) -> Path:
    target = destination / "target"
    for directory in ("usr/bin", "usr/sbin", "opt/suderra-test"):
        (target / directory).mkdir(parents=True, exist_ok=True)
    (target / "sbin").symlink_to("usr/sbin")
    (target / "bin").symlink_to("usr/bin")
    busybox = target / "usr/bin/busybox"
    busybox.write_bytes(ELF)
    busybox.chmod(0o755)
    hidden = target / "opt/suderra-test/real-tool"
    hidden.write_bytes(ELF)
    hidden.chmod(0o755)
    for script, entry in manifest["scripts"].items():
        if script in drop:
            continue
        path = target / script
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / entry["source"], path)
        path.chmod(0o755)
    count = 0
    for script, entry in manifest["scripts"].items():
        if script in drop:
            continue
        for group in entry["groups"]:
            for name in group["commands"]:
                if name in skip:
                    continue
                path = target / name.lstrip("/") if "/" in name else target / "usr/sbin" / name
                if path.exists() or path.is_symlink():
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                count += 1
                # The three kinds of provider an image has: a real binary, a
                # BusyBox applet (relative link), a link into another directory
                # by an absolute target that exists only inside the image.
                if name in ("cat", "sed", "grep"):
                    path.symlink_to("../bin/busybox")
                elif name == "awk":
                    path.symlink_to("/opt/suderra-test/real-tool")
                else:
                    # A compiled program, not a script of this OS.
                    path.write_bytes(ELF)
                    path.chmod(0o755)
    return target


def run_gate(target: Path, variant: str, arch: str, config: str = ALL_CONFIG, manifest_file: Path = manifest_path):
    config_file = target.parent / "config"
    config_file.write_text(config, encoding="utf-8")
    return ctc.check(target, manifest_file, variant, arch, config_file)


def gate_ok(description: str, target: Path, variant: str, arch: str, **kwargs) -> None:
    problems = run_gate(target, variant, arch, **kwargs)
    expect(not problems, f"gate: {description}: expected a pass, got {problems}")


def gate_fails(description: str, target: Path, variant: str, arch: str, needle: str, **kwargs) -> None:
    problems = run_gate(target, variant, arch, **kwargs)
    expect(
        any(needle in problem for problem in problems),
        f"gate: {description}: expected a problem mentioning {needle!r}, got {problems}",
    )


def fresh(name: str, skip: set[str] = frozenset(), drop: frozenset[str] = DEVICE_IMAGE) -> Path:
    destination = work / name
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    return make_target(destination, skip, drop)


base = fresh("base")
gate_ok("a complete prod x86_64 image", base, "prod", "x86_64")
gate_ok("a complete prod aarch64 image", base, "prod", "aarch64")
gate_ok("a complete dev image", base, "dev", "x86_64")

# EI-078: mkfs.ext4 missing on a production image.
no_mkfs = fresh("no-mkfs", {"mkfs.ext4"})
gate_fails("EI-078: no mkfs.ext4 in a production image", no_mkfs, "prod", "x86_64", "mkfs.ext4")
gate_ok("no mkfs.ext4 in a dev image (the dev /data is a plain partition)", no_mkfs, "dev", "x86_64")
# A command that exists only as a dangling link does not exist.
dangling = fresh("dangling", {"mkfs.ext4"})
(dangling / "usr/sbin/mkfs.ext4").symlink_to("../bin/mke2fs-missing")
gate_fails("a dangling link", dangling, "prod", "x86_64", "mkfs.ext4")
# A file without the executable bit does not run.
not_exec = fresh("not-exec")
(not_exec / "usr/sbin/mkfs.ext4").chmod(0o644)
gate_fails("a non-executable provider", not_exec, "prod", "x86_64", "mkfs.ext4")
# The host's own binaries must not satisfy an image: an absolute link resolves
# inside the image.
escape = fresh("escape", {"mkfs.ext4"})
(escape / "usr/sbin/mkfs.ext4").symlink_to("/usr/sbin/mke2fs")
gate_fails("an absolute link must resolve inside the image, not on the host", escape, "prod", "x86_64", "mkfs.ext4")

# Production-only commands.
for name in ("cryptsetup", "systemd-cryptenroll", "blkid"):
    missing = fresh(f"no-{name}", {name})
    gate_fails(f"production needs {name}", missing, "prod", "x86_64", name)
    gate_ok(f"dev needs no {name}", missing, "dev", "x86_64")

# Architecture conditions: GRUB's tools on x86_64, U-Boot's on aarch64.
no_grub = fresh("no-grub", {"grub-editenv"})
gate_fails("x86_64 needs grub-editenv", no_grub, "prod", "x86_64", "grub-editenv")
gate_ok("aarch64 needs no grub-editenv", no_grub, "prod", "aarch64")
no_uboot = fresh("no-uboot", {"fw_printenv"})
gate_fails("aarch64 needs fw_printenv", no_uboot, "prod", "aarch64", "fw_printenv")
gate_ok("x86_64 needs no fw_printenv", no_uboot, "prod", "x86_64")

# Configuration conditions.
no_installer = fresh(
    "no-installer",
    {"/usr/bin/suderra-installer"},
    DEVICE_IMAGE | {"usr/sbin/suderra-rauc-health-gate", "usr/sbin/suderra-rauc-mark-good"},
)
gate_fails("the installer image needs suderra-installer", no_installer, "prod", "x86_64", "suderra-installer")
gate_ok(
    "an image without the installer needs no suderra-installer",
    no_installer,
    "prod",
    "x86_64",
    config="BR2_PACKAGE_RAUC=y\nBR2_PACKAGE_SUDERRA_OTA=y\n",
)

# Optional groups: the script copes with their absence.
optional = fresh("optional", {"tpm2_createek", "tpm2_flushcontext", "dmsetup", "ss"})
gate_ok("optional commands may be absent", optional, "prod", "x86_64")

# A script that runs a command the manifest does not declare.
undeclared = fresh("undeclared")
with (undeclared / "usr/sbin/suderra-data-unlock").open("a", encoding="utf-8") as handle:
    handle.write('\nwipefs -a "$1"\n')
gate_fails("a command the manifest does not declare", undeclared, "prod", "x86_64", "wipefs")

# A manifest entry for a command the script no longer runs.
stale_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
stale_manifest["scripts"]["usr/sbin/suderra-data-unlock"]["groups"][0]["commands"].append("ghost-command")
stale_path = work / "stale.json"
stale_path.write_text(json.dumps(stale_manifest), encoding="utf-8")
gate_fails("a stale manifest entry", fresh("stale"), "prod", "x86_64", "declares `ghost-command`", manifest_file=stale_path)

# A shell script of the image that nobody declared.
unregistered = fresh("unregistered")
extra = unregistered / "usr/sbin/suderra-extra"
extra.write_text("#!/bin/sh\nls\n", encoding="utf-8")
extra.chmod(0o755)
gate_fails("an undeclared shipped script", unregistered, "prod", "x86_64", "suderra-extra")

# A command word built at run time cannot be checked.
dynamic = fresh("dynamic")
with (dynamic / "usr/sbin/suderra-data-unlock").open("a", encoding="utf-8") as handle:
    handle.write('\n"${UNKNOWN_TOOL}" run\n')
gate_fails("a dynamic command word", dynamic, "prod", "x86_64", "built at run time")

# A script the parser refuses fails the gate instead of passing unchecked.
refused = fresh("refused")
with (refused / "usr/sbin/suderra-data-unlock").open("a", encoding="utf-8") as handle:
    handle.write('\necho "unterminated\n')
gate_fails("a script that cannot be parsed", refused, "prod", "x86_64", "unterminated")

# The USB installer image ships the self-installer and needs what it runs.
installer_image = fresh("installer-image", set(), frozenset())
gate_ok("the USB installer image", installer_image, "prod", "aarch64")
no_xz = fresh("installer-no-xz", {"xz"}, frozenset())
gate_fails("the self-installer needs xz", no_xz, "prod", "aarch64", "xz")

# A script that is not part of the image is skipped, not an error.
partial = fresh("partial")
(partial / "usr/sbin/suderra-runtime-scenario").unlink()
gate_ok("an image without the runtime scenario driver", partial, "prod", "x86_64")

# The command line: exit status and message.
config_file = base.parent / "config"
config_file.write_text(ALL_CONFIG, encoding="utf-8")
ok = subprocess.run(
    [sys.executable, "-I", str(root / "scripts/ci/check-target-commands.py"), "check",
     "--target", str(base), "--manifest", str(manifest_path), "--variant", "prod",
     "--arch", "x86_64", "--config", str(config_file)],
    capture_output=True, text=True, check=False,
)
expect(ok.returncode == 0, f"cli: a complete image failed: {ok.stderr}")
bad = subprocess.run(
    [sys.executable, "-I", str(root / "scripts/ci/check-target-commands.py"), "check",
     "--target", str(no_mkfs), "--manifest", str(manifest_path), "--variant", "prod",
     "--arch", "x86_64", "--config", str(no_mkfs.parent / "config")],
    capture_output=True, text=True, check=False,
)
expect(bad.returncode == 1 and "mkfs.ext4" in bad.stderr, f"cli: a missing mkfs.ext4 must exit 1 naming it: {bad.returncode} {bad.stderr}")

# post-build.sh runs the gate, last, with the image's variant and architecture.
post_build = (root / "board/suderra/common/post-build.sh").read_text(encoding="utf-8")
expect("check-target-commands.py" in post_build, "post-build.sh does not run check-target-commands.py")
expect(
    post_build.rindex("check-target-commands.py") > post_build.rindex("Appliance lockdown"),
    "post-build.sh must run the command gate after the image's scripts are kept, removed or rewritten",
)

if failures:
    print("\n".join(f"ERROR: {line}" for line in failures), file=sys.stderr)
    sys.exit(1)
print(f"parser and gate: {len(SNIPPETS)} snippets, synthetic targets ok")
PY

# --- Config.in selects e2fsprogs for every image ----------------------------------------------
resolve() {
    # resolve <external-tree> <defconfig> <output-dir>
    make -s -C "${ROOT}/buildroot" BR2_EXTERNAL="$1" O="$3" "$2" > "$3.log" 2>&1 ||
        fail "Buildroot could not resolve $2 (see $3.log): $(tail -n 5 "$3.log")"
}

mapfile -t defconfigs < <(cd "${ROOT}/configs" && ls ./*_defconfig | sed 's#^\./##')
[ "${#defconfigs[@]}" -ge 9 ] || fail "expected at least 9 defconfigs, found ${#defconfigs[@]}"
for defconfig in "${defconfigs[@]}"; do
    out="${WORK}/resolved-${defconfig%_defconfig}"
    resolve "${ROOT}" "${defconfig}" "${out}"
    grep -qx 'BR2_PACKAGE_E2FSPROGS=y' "${out}/.config" ||
        fail "${defconfig}: the resolved .config does not select e2fsprogs (mkfs.ext4 and e2fsck would be missing, EI-078)"
    grep -qx 'BR2_PACKAGE_SUDERRA_DATA_TOOLS=y' "${out}/.config" ||
        fail "${defconfig}: the /data tools option is not on"
    if grep -q '^BR2_PACKAGE_SUDERRA_DATA_TOOLS' "${ROOT}/configs/${defconfig}" ||
        grep -q '^BR2_PACKAGE_E2FSPROGS' "${ROOT}/configs/${defconfig}"; then
        fail "${defconfig}: e2fsprogs must come from Config.in, not from the defconfig"
    fi
done

# The same resolution of an external tree without the select must fail the
# assertion above: the check is not vacuous.
mutated="${WORK}/mutated-external"
mkdir -p "${mutated}"
cp -r "${ROOT}/Config.in" "${ROOT}/external.desc" "${ROOT}/external.mk" "${ROOT}/configs" "${ROOT}/package" "${mutated}/"
python3 -I - "${mutated}/Config.in" << 'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
mutated = text.replace("\tselect BR2_PACKAGE_E2FSPROGS\n", "")
if mutated == text:
    sys.exit("ERROR: Config.in no longer selects BR2_PACKAGE_E2FSPROGS in the form this test mutates")
open(path, "w", encoding="utf-8").write(mutated)
PY
resolve "${mutated}" suderra_qemu_x86_64_prod_ab_defconfig "${WORK}/resolved-mutated"
if grep -qx 'BR2_PACKAGE_E2FSPROGS=y' "${WORK}/resolved-mutated/.config"; then
    fail "an external tree without the select still resolves e2fsprogs: something else selects it and this test proves nothing"
fi

echo "target commands contract passed"
