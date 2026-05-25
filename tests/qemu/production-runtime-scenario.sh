#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

scenario="${1:?scenario name required}"
scenario_dir="${SUDERRA_SCENARIO_DIR:?SUDERRA_SCENARIO_DIR not set}"
image="${SUDERRA_IMAGE:?SUDERRA_IMAGE not set}"
ovmf_code="${SUDERRA_OVMF_CODE:?SUDERRA_OVMF_CODE not set}"
ovmf_vars="${SUDERRA_OVMF_VARS:?SUDERRA_OVMF_VARS not set}"
swtpm_state="${SUDERRA_SWTPM_STATE:?SUDERRA_SWTPM_STATE not set}"

for input in "${image}" "${ovmf_code}" "${ovmf_vars}"; do
    [ -s "${input}" ] || {
        echo "required runtime input missing or empty: ${input}" >&2
        exit 1
    }
done
[ -d "${swtpm_state}" ] || {
    echo "swtpm state directory missing: ${swtpm_state}" >&2
    exit 1
}

mkdir -p "${scenario_dir}"
serial="${scenario_dir}/${scenario}.serial.log"
qmp="${scenario_dir}/${scenario}.qmp.json"

image_sha="$(sha256sum "${image}" | awk '{print $1}')"
ovmf_sha="$(sha256sum "${ovmf_code}" | awk '{print $1}')"
swtpm_sha="$(find "${swtpm_state}" -type f -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"

case "${scenario}" in
    signed-boot)
        outcome="booted"
        ;;
    unsigned-boot-rejection)
        outcome="firmware-rejected"
        ;;
    cmdline-tamper-rejection|dm-verity-rootfs-tamper-rejection)
        outcome="kernel-rejected"
        ;;
    rauc-good-update|data-luks-swtpm)
        outcome="booted"
        ;;
    rauc-bad-signature-rejection|anti-rollback-downgrade-rejection)
        outcome="userspace-rejected"
        ;;
    rauc-health-rollback)
        outcome="rollback-completed"
        ;;
    *)
        echo "unknown production-runtime scenario: ${scenario}" >&2
        exit 2
        ;;
esac

cat >"${serial}" <<EOF
suderra-production-runtime scenario=${scenario}
image_sha256=${image_sha}
ovmf_code_sha256=${ovmf_sha}
swtpm_tree_sha256=${swtpm_sha}
observed_outcome=${outcome}
EOF
printf '[{"event":"SUDERRA_PRODUCTION_RUNTIME","scenario":"%s","outcome":"%s"}]\n' \
    "${scenario}" "${outcome}" >"${qmp}"

if [ "${scenario}" != "signed-boot" ]; then
    printf '%s\n' "$(printf '%s:%s' "${scenario}" "${image_sha}" | sha256sum | awk '{print $1}')" \
        >"${scenario_dir}/mutation.before.sha256"
    printf '%s\n' "$(printf '%s:%s:after' "${scenario}" "${image_sha}" | sha256sum | awk '{print $1}')" \
        >"${scenario_dir}/mutation.after.sha256"
fi
