#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"
POST_BUILD="${PROJECT_ROOT}/board/suderra/common/post-build.sh"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_IMAGE}"
grep -q 'BR2 production variant cannot be downgraded with SUDERRA_VARIANT=dev' "${POST_IMAGE}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_IMAGE}"
grep -q 'enforce_production_contract' "${POST_IMAGE}"
grep -q 'SUDERRA_INSTALLER_PAYLOAD_PUBKEY must point to the pinned Ed25519 public key' "${POST_IMAGE}"
grep -q 'openssl pkeyutl -verify -rawin -pubin' "${POST_IMAGE}"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_BUILD}"
grep -q 'BR2 production variant cannot be downgraded with SUDERRA_VARIANT=dev' "${POST_BUILD}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_BUILD}"
