#!/usr/bin/env bash
#
# /data at-rest LUKS2 provisioning sözleşmesi (RT-1).
#
# suderra-data-unlock'un PROD yolunda /data'yı ilk boot'ta LUKS2 olarak provision
# edip anahtarı TPM2'ye seal ettiğini (fail-closed, blank-only) ve gerekli paket
# desteğinin prod defconfig'lerde açık olduğunu STATİK olarak kanıtlar. Gerçek
# TPM seal/unseal donanım/swtpm ister (G5) — burada değil. LUKS mekaniği
# (format/open/mkfs) loopback ile ayrıca doğrulanır (bkz. commit / CI).
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
UNLOCK="${ROOT}/board/suderra/common/rootfs-overlay/usr/sbin/suderra-data-unlock"

[ -f "${UNLOCK}" ] || { echo "ERROR: suderra-data-unlock yok" >&2; exit 1; }

script="$(cat "${UNLOCK}")"
need() {
    # need <insan-açıklaması> <grep-deseni>
    grep -Eq -- "$2" <<<"${script}" || { echo "ERROR: suderra-data-unlock eksik: $1" >&2; exit 1; }
}

# 1. Provisioning mantığı mevcut ve fail-closed.
need "provision_luks_data fonksiyonu"            'provision_luks_data\(\)'
need "blank-only güvenlik guard'ı (bölümün kendi imzası: blkid -p TYPE/PTTYPE)" 'blkid -p -s TYPE -s PTTYPE -o value'
need "TPM2 zorunlu (fail-closed) kontrolü"       '/dev/tpmrm0|/dev/tpm0'
need "LUKS2 formatlama"                          'cryptsetup luksFormat --type luks2'
need "TPM2 seal (systemd-cryptenroll)"           'systemd-cryptenroll'
need "TPM2 device auto"                          '--tpm2-device=auto'
need "PCR7 binding"                              'tpm2-pcrs=7'
need "ephemeral passphrase slot'unun silinmesi"  'luksKillSlot'
need "fresh volume'da mkfs.ext4"                 'mkfs.ext4 .* "\$\{mapper_dev\}"'

# 2. Ephemeral anahtar KALICI depoya yazılmamalı — yalnız /run (tmpfs).
grep -Eq 'mktemp /run/' <<<"${script}" || {
    echo "ERROR: ephemeral anahtar /run (tmpfs) dışında üretiliyor olabilir" >&2; exit 1; }

# 3. Prod defconfig'ler TPM2 LUKS unlock/seal desteğini içermeli. NOT: ayrı bir
# BR2_PACKAGE_SYSTEMD_CRYPTSETUP sembolü YOKTUR — cryptsetup + tpm2-tss, systemd'yi
# -Dlibcryptsetup=enabled + -Dtpm2=enabled ile derletir (buildroot systemd.mk),
# yani systemd-cryptsetup/systemd-cryptenroll --tpm2 bunlardan üretilir.
for dc in suderra_x86_64_defconfig suderra_aarch64_rpi4_prod_ab_defconfig \
          suderra_aarch64_revpi4_prod_ab_defconfig suderra_qemu_x86_64_prod_ab_defconfig; do
    f="${ROOT}/configs/${dc}"
    [ -f "${f}" ] || { echo "ERROR: ${dc} yok" >&2; exit 1; }
    for pkg in BR2_PACKAGE_CRYPTSETUP BR2_PACKAGE_TPM2_TSS BR2_PACKAGE_TPM2_TOOLS; do
        grep -q "^${pkg}=y" "${f}" || { echo "ERROR: ${dc} eksik: ${pkg}" >&2; exit 1; }
    done
done

# 4. DEV donanım defconfig'leri cryptsetup İÇERMEMELİ (dev /data = düz ext4,
# tasarım gereği). TPM2 araçları LUKS değildir: boards.json bir kartı
# tpm-ek-sha256 ile bağlıyorsa suderra-identity EK'yi tpm2_createek ile okur
# (ADR-048 DEC-3.6), bu yüzden o kartın HER imajı (dev dahil) tpm2-tss ve
# tpm2-tools taşır; aksi halde dev imajı hiç provision edilemez.
for dc in suderra_aarch64_rpi4_defconfig suderra_aarch64_revpi4_defconfig; do
    f="${ROOT}/configs/${dc}"
    if grep -qE '^BR2_PACKAGE_CRYPTSETUP=y' "${f}"; then
        echo "ERROR: dev ${dc} cryptsetup içermemeli (dev /data düz ext4)" >&2; exit 1; fi
done
python3 -I - "${ROOT}" <<'PY'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
boards = json.loads((root / "contracts/suderra-edge/v1/boards.json").read_text(encoding="utf-8"))
problems = []
for board in boards["boards"]:
    if board["device_binding_method"] != "tpm-ek-sha256":
        continue
    for image in board["os_images"]:
        text = (root / "configs" / image["defconfig"]).read_text(encoding="utf-8")
        have = set(re.findall(r"^(BR2_[A-Za-z0-9_]+)=y(?:\s|$)", text, re.M))
        for pkg in ("BR2_PACKAGE_TPM2_TSS", "BR2_PACKAGE_TPM2_TOOLS"):
            if pkg not in have:
                problems.append(f"{image['defconfig']} ({board['board_profile']}, tpm-ek-sha256) must select {pkg}")
if problems:
    sys.exit("ERROR: " + "; ".join(problems))
PY

# 5. Provisioning is a transaction (EI-078). From the luksFormat on, every
# failure is a rollback to a blank partition: alarm is the one exit and it rolls
# back, the volume carries the provisioning label until the last step, and the
# only place that erases keyslots also zeroes the header (`cryptsetup erase`
# alone leaves a LUKS header that blkid and isLuks still see, so a "clean retry"
# never happened). A failed mkfs.ext4 is an alarm, not a bare command under set -e.
python3 -I - "${UNLOCK}" "${ROOT}/contracts/suderra-edge/v1/schemas/result.schema.json" <<'PY'
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
schema = json.load(open(sys.argv[2], encoding="utf-8"))
errors = []

def function_body(name):
    match = re.search(r"^" + name + r"\(\) \{\n(.*?)^\}", text, re.S | re.M)
    if not match:
        errors.append(f"suderra-data-unlock has no function {name}")
        return ""
    return match.group(1)

alarm = function_body("alarm")
if "rollback_provisioning" not in alarm:
    errors.append("alarm must roll back an uncommitted volume: it is the one exit of every failure path")
provision = function_body("provision_luks_data")
if provision.find('PROVISIONING_DEVICE="${dev}"') < 0 or provision.find('PROVISIONING_DEVICE="${dev}"') > provision.find("cryptsetup luksFormat"):
    errors.append("provision_luks_data must mark the volume as uncommitted before luksFormat, so no failure after it can skip the rollback")
if "--label \"${LABEL_PROVISIONING}\"" not in provision:
    errors.append("luksFormat must label the volume with the provisioning marker, so an interrupted provisioning is recognised at the next boot")
blank = function_body("blank_data_partition")
if "cryptsetup erase" not in blank or "dd if=/dev/zero" not in blank or "has_signature" not in blank:
    errors.append("blank_data_partition must erase the keyslots, zero the header and verify with has_signature that the partition is blank")
# A partition of a GPT disk is never "blank" to plain `blkid <dev>`: it reports the
# partition entry (PARTLABEL, PARTUUID) of every partition, so classifying by it
# refuses to provision the blank data partition of the production disk. The
# signature test asks for the tags of what is written in the partition only.
if re.search(r'blkid "\$', text) or re.search(r'\bblkid "\$\{?dev', text):
    errors.append("a plain blkid on the data partition reports its partition entry as a signature: use has_signature")
if not re.search(r'blkid -p -s TYPE -s PTTYPE -o value', function_body("has_signature")):
    errors.append("has_signature must probe the partition for TYPE and PTTYPE only (low-level, no cache)")
if "has_signature" not in function_body("classify_data_partition"):
    errors.append("classify_data_partition must use has_signature to tell a blank partition from a foreign one")
if len(re.findall(r"cryptsetup erase", text)) != 1:
    errors.append("cryptsetup erase appears outside blank_data_partition: it leaves a LUKS header behind (isLuks and blkid still see it)")
if not re.search(r'mkfs\.ext4 [^\n]*"\$\{mapper_dev\}"\s*\|\|\s*\n\s*alarm ', text):
    errors.append("a failed mkfs.ext4 must be an alarm, which rolls the fresh volume back")
commit = function_body("commit_provisioning")
if "LABEL_COMMITTED" not in commit or 'PROVISIONING_DEVICE=""' not in commit:
    errors.append("commit_provisioning must label the volume committed and end the transaction")
if text.rfind("commit_provisioning") < text.rfind("lifecycle factory"):
    errors.append("the transaction must commit after the lifecycle store was created: nothing may follow the commit that can fail")
if "trap cleanup_secrets EXIT" not in text:
    errors.append("the ephemeral key file must be removed however the script ends (trap EXIT)")

# The recovery slot (DEC-14.3): provisioning escrows a random key, recovery
# uses it and replaces it.
if len(re.findall(r"tpm2-pcrs=", text)) != 1 or not re.search(r'^TPM2_SEAL_OPTIONS="[^"]*--tpm2-pcrs=7', text, re.M):
    errors.append("the TPM2 policy must be stated once, in TPM2_SEAL_OPTIONS, for the provisioning and the re-seal alike")
for fragment in ("rsa_padding_mode:oaep", "rsa_oaep_md:sha256", "rsa_mgf1_md:sha256"):
    if fragment not in function_body("write_escrow"):
        errors.append(f"write_escrow must encrypt with RSA-OAEP and SHA-256: {fragment} is missing")
if 'ESCROW_PUBKEY=/etc/suderra/recovery-escrow.pub.pem' not in text:
    errors.append("the escrow public key must be the image's /etc/suderra/recovery-escrow.pub.pem")
provision = function_body("provision_luks_data")
if provision.find("write_escrow") < 0 or provision.find("write_escrow") > provision.find("cryptsetup luksFormat"):
    errors.append("the recovery key must be escrowed before luksFormat: nothing is formatted unless the escrow works")
# A failed escrow is an alarm, on the statement itself: `write_escrow ... || true`
# (or any other way to carry on) would format a volume whose recovery key nobody
# holds. The order check above passes such a script; the VM test catches it only
# through a second guard.
for name in ("provision_luks_data", "recover_prod_luks_data"):
    if not re.search(r'write_escrow [^\n]*\|\|\s*\n\s*alarm [a-z-]+ "', function_body(name)):
        errors.append(f"{name}: a failed write_escrow must be an alarm on that statement, before anything is formatted or changed")
if "/dev/urandom" not in function_body("new_recovery_key"):
    errors.append("the recovery key must come from /dev/urandom")
if "--disable-external-tokens" not in function_body("add_recovery_slot"):
    errors.append("a recovery slot is added with the key file alone, never with a token")
if text.count("mktemp") != 1 or "mktemp /run/" not in function_body("new_temp"):
    errors.append("every file that holds key material is made by new_temp under /run")
if not re.search(r'luksKillSlot[^\n]*--key-file "\$\{recovery_file\}"', provision):
    errors.append("provisioning must remove the ephemeral slot with the recovery key, which proves the recovery slot")
recover = function_body("recover_prod_luks_data")
if not recover:
    errors.append("suderra-data-unlock has no recover mode")
else:
    consume = recover.find('rm -f "${RECOVERY_KEY_INPUT}"')
    check = recover.find("grep -Eqx '[0-9a-f]{64}'")
    if consume < 0 or check < 0 or consume > check:
        errors.append("recover must consume the key file before it judges it, or a path unit retries a rejected key forever")
    if "--test-passphrase --disable-external-tokens --key-slot" not in recover:
        errors.append("recover must check the key against the recovery slots alone, with tokens disabled: a volume that still unseals must not accept a wrong key")
    opened = recover.find("cryptsetup open --disable-external-tokens")
    flagged = recover.find("RECOVERING=1")
    if opened < 0 or flagged < opened:
        errors.append("RECOVERING must be set after recover opened the volume: a refusal must never close a volume the boot opened")
    wipe = recover.find("--wipe-slot=tpm2")
    seal = recover.find("seal_to_tpm")
    if wipe < 0 or seal < wipe:
        errors.append("recover must wipe the old TPM2 seal before it seals again: systemd-cryptenroll does nothing for a PCR set that is already enrolled")
    if recover.find("add_recovery_slot") > recover.find("seal_to_tpm") or recover.find("luksKillSlot") < recover.find("seal_to_tpm"):
        errors.append("recover must add the new recovery slot first and remove the old ones after the seal, so every step leaves a working key")
    if "mkfs" in recover or "luksFormat" in recover:
        errors.append("recover must never format")
if 'recover)' not in text or 'recovery exists for production volumes only' not in text:
    errors.append("the recover mode must exist for production volumes only")

# Every reason the script records must be one the contract allows for a
# data-unlock result: suderra-installer refuses the others and the alarm then
# records nothing.
allowed = None
for clause in schema["allOf"]:
    if clause["if"]["properties"]["kind"].get("const") == "data-unlock":
        allowed = set(clause["then"]["properties"]["reason"]["enum"])
reasons = set(re.findall(r'\balarm ([a-z0-9]+(?:-[a-z0-9]+)*) +"', text))
if not reasons:
    errors.append("no alarm reason found in suderra-data-unlock")
for reason in sorted(reasons - allowed):
    errors.append(f"suderra-data-unlock records the reason {reason!r}, which the data-unlock result contract does not allow ({sorted(allowed)})")
if errors:
    sys.exit("ERROR: " + "; ".join(errors))
PY

# 6. The recovery units: the path unit watches the very file the script
# consumes, the service runs the recover mode and reboots only after it
# succeeded, and only production images enable them.
UNITS="${ROOT}/board/suderra/common/rootfs-overlay/etc/systemd/system"
grep -qx 'PathExists=/run/suderra-os/data-recovery.key' "${UNITS}/suderra-data-recovery.path" ||
    { echo "ERROR: suderra-data-recovery.path must watch /run/suderra-os/data-recovery.key" >&2; exit 1; }
grep -qx 'RECOVERY_KEY_INPUT=/run/suderra-os/data-recovery.key' "${UNLOCK}" ||
    { echo "ERROR: suderra-data-unlock and suderra-data-recovery.path must agree on the key file" >&2; exit 1; }
grep -qx 'Unit=suderra-data-recovery.service' "${UNITS}/suderra-data-recovery.path" ||
    { echo "ERROR: the recovery path unit must start suderra-data-recovery.service" >&2; exit 1; }
grep -qx 'ExecStart=/usr/sbin/suderra-data-unlock recover' "${UNITS}/suderra-data-recovery.service" ||
    { echo "ERROR: suderra-data-recovery.service must run suderra-data-unlock recover" >&2; exit 1; }
grep -qx 'ExecStartPost=/usr/bin/systemctl --no-block reboot' "${UNITS}/suderra-data-recovery.service" ||
    { echo "ERROR: the recovery must reboot after it succeeded (ExecStartPost), which proves the new seal" >&2; exit 1; }
if grep -qE '^(Restart|ProtectSystem|PrivateTmp|ReadWritePaths|ProtectHome)=' "${UNITS}/suderra-data-recovery.service"; then
    echo "ERROR: suderra-data-recovery.service must neither restart nor use mount-namespace options: it opens and mounts the volume" >&2
    exit 1
fi
python3 -I - "${ROOT}/board/suderra/common/post-build.sh" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r'if \[ "\$\{SUDERRA_OS_VARIANT\}" = "prod" \]; then\n\s*#[^\n]*\n\s*#[^\n]*\n\s*enable_unit suderra-data-recovery\.path paths\.target\n\s*preset_enable suderra-data-recovery\.path', text)
if not match:
    sys.exit("ERROR: post-build.sh must enable suderra-data-recovery.path on production images only")
block = re.search(r'production_device_image=1\nif \[ "\$\{SUDERRA_OS_VARIANT\}" != "prod" \]; then\n\s*production_device_image=0\nfi\ncase "\$\{DEFCONFIG_NAME\}" in\n\s*\*usb_installer\*\) production_device_image=0 ;;\nesac\nif \[ "\$\{production_device_image\}" = "0" \]; then(.*?)\nfi\n', text, re.S)
if not block or "suderra-data-recovery.path" not in block.group(1) or "suderra-data-recovery.service" not in block.group(1):
    sys.exit("ERROR: post-build.sh must delete the recovery units from images that are not production device images")
PY

echo "/data LUKS provisioning contract passed"
