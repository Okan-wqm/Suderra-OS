#!/usr/bin/env bash
#
# Create a signed x86_64 RAUC update bundle from production build artifacts.

set -euo pipefail
IFS=$'\n\t'

usage() {
    cat <<'EOF'
Usage:
  create-rauc-bundle.sh x86 <BINARIES_DIR> <VERSION> <OUTPUT.raucb>

Required environment:
  SUDERRA_RAUC_SIGNING_CERT      RAUC bundle signing certificate

Optional environment:
  SUDERRA_RAUC_SIGNING_KEY       Dev/lab RAUC bundle signing private key
  SUDERRA_RAUC_PKCS11_URI        Production RAUC PKCS#11 private key URI
  SUDERRA_HSM_SIGNING_EVIDENCE   Production HSM session/key evidence JSON
  SUDERRA_RAUC_KEYRING           Keyring used to verify the generated bundle
  SUDERRA_RAUC                   RAUC host tool path
  HOST_DIR                       Buildroot host dir containing bin/rauc
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

need_file() {
    [ -s "$1" ] || die "required file missing or empty: $1"
}

production_mode() {
    [ "${SUDERRA_SIGNING_MODE:-}" = "prod" ] || [ "${SUDERRA_RELEASE_TIER:-}" = "production" ]
}

reject_prod_file_key() {
    local value="$1"
    if ! production_mode; then
        return 0
    fi
    case "${value}" in
        pkcs11:*)
            ;;
        pkcs11:object=*|pkcs11:token=*)
            ;;
        "")
            die "SUDERRA_RAUC_PKCS11_URI must be set for production RAUC signing"
            ;;
        *)
            die "production RAUC signing rejects file-backed private keys: ${value}"
            ;;
    esac
}

production_signing_evidence() {
    local evidence="${SUDERRA_HSM_SIGNING_EVIDENCE:-}"
    local uri="${SUDERRA_RAUC_PKCS11_URI:-}"
    local script_dir

    [ -n "${evidence}" ] || die "SUDERRA_HSM_SIGNING_EVIDENCE must be set for production RAUC signing"
    need_file "${evidence}"
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    python3 "${script_dir}/evidence/validate-hsm-signing-evidence.py" validate \
        "${evidence}" \
        --pkcs11-uri "${uri}" \
        --certificate "${SUDERRA_RAUC_SIGNING_CERT}" \
        --require-production \
        >/dev/null || die "HSM signing evidence validation failed"
}

resolve_rauc() {
    local candidate="${SUDERRA_RAUC:-}"

    if [ -n "${candidate}" ]; then
        [ -x "${candidate}" ] || die "SUDERRA_RAUC is not executable: ${candidate}"
        printf '%s\n' "${candidate}"
        return 0
    fi
    if [ -n "${HOST_DIR:-}" ] && [ -x "${HOST_DIR}/bin/rauc" ]; then
        printf '%s\n' "${HOST_DIR}/bin/rauc"
        return 0
    fi
    if command -v rauc >/dev/null 2>&1; then
        command -v rauc
        return 0
    fi
    die "rauc host tool is required to create signed bundles"
}

sha256_of() {
    sha256sum "$1" | awk '{print $1}'
}

size_of() {
    wc -c < "$1" | awk '{print $1}'
}

stage_file() {
    local src="$1"
    local dst="$2"

    need_file "${src}"
    install -D -m 0644 "${src}" "${dst}"
}

write_manifest() {
    local manifest="$1"
    local version="$2"
    local rootfs="$3"
    local verity="$4"

    cat > "${manifest}" <<EOF
[update]
compatible=suderra-os-x86_64
version=${version}

[bundle]
format=verity

[hooks]
filename=suderra-rauc-x86-slot-hook.sh

[image.rootfs]
filename=$(basename "${rootfs}")
size=$(size_of "${rootfs}")
sha256=$(sha256_of "${rootfs}")
hooks=post-install

[image.rootfs-verity]
filename=$(basename "${verity}")
size=$(size_of "${verity}")
sha256=$(sha256_of "${verity}")
EOF
}

create_x86_bundle() {
    local binaries_dir="$1"
    local version="$2"
    local output="$3"
    local rauc_tool
    local signing_key="${SUDERRA_RAUC_SIGNING_KEY:-}"
    local signing_cert="${SUDERRA_RAUC_SIGNING_CERT:-}"
    local keyring="${SUDERRA_RAUC_KEYRING:-}"
    local script_dir
    local stage_dir
    local rootfs
    local verity

    [ -n "${version}" ] || die "version must not be empty"
    case "${version}" in
        *[!A-Za-z0-9._+-]*)
            die "version contains unsupported characters: ${version}"
            ;;
    esac
    if production_mode; then
        if [ -n "${signing_key}" ]; then
            reject_prod_file_key "${signing_key}"
        fi
        reject_prod_file_key "${SUDERRA_RAUC_PKCS11_URI:-}"
        production_signing_evidence
        signing_key="${SUDERRA_RAUC_PKCS11_URI}"
    fi
    [ -n "${signing_key}" ] || die "SUDERRA_RAUC_SIGNING_KEY must be set"
    [ -n "${signing_cert}" ] || die "SUDERRA_RAUC_SIGNING_CERT must be set"
    case "${signing_key}" in
        pkcs11:*) ;;
        *) need_file "${signing_key}" ;;
    esac
    need_file "${signing_cert}"

    rauc_tool="$(resolve_rauc)"
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    stage_dir="$(mktemp -d)"
    trap 'rm -rf "${stage_dir}"' EXIT

    rootfs="${stage_dir}/rootfs.img"
    verity="${stage_dir}/rootfs-verity.img"

    stage_file "${binaries_dir}/rootfs.ext4" "${rootfs}"
    stage_file "${binaries_dir}/rootfs.verity" "${verity}"
    stage_file "${binaries_dir}/suderra-A.efi" "${stage_dir}/suderra-A.efi"
    stage_file "${binaries_dir}/suderra-B.efi" "${stage_dir}/suderra-B.efi"
    stage_file "${script_dir}/rauc-x86-slot-hook.sh" "${stage_dir}/suderra-rauc-x86-slot-hook.sh"
    chmod 0755 "${stage_dir}/suderra-rauc-x86-slot-hook.sh"

    write_manifest "${stage_dir}/manifest.raucm" "${version}" "${rootfs}" "${verity}"
    rm -f "${output}"
    "${rauc_tool}" bundle \
        --cert="${signing_cert}" \
        --key="${signing_key}" \
        "${stage_dir}" \
        "${output}"
    need_file "${output}"

    if [ -n "${keyring}" ]; then
        need_file "${keyring}"
        "${rauc_tool}" info --keyring="${keyring}" "${output}" >/dev/null
    fi
}

command="${1:-}"
case "${command}" in
    x86)
        [ "$#" -eq 4 ] || {
            usage >&2
            exit 2
        }
        create_x86_bundle "$2" "$3" "$4"
        ;;
    --help|-h|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
