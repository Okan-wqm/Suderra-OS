#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd -- "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
POST_IMAGE="${PROJECT_ROOT}/board/suderra/common/post-image.sh"
POST_BUILD="${PROJECT_ROOT}/board/suderra/common/post-build.sh"
SIGN_BUNDLE="${PROJECT_ROOT}/scripts/sign-bundle.sh"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_IMAGE}"
grep -q 'BR2 Suderra variant.*conflicts with SUDERRA_VARIANT' "${POST_IMAGE}"
grep -q 'requires BR2_CONFIG or SUDERRA_VARIANT' "${POST_IMAGE}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_IMAGE}"
grep -q 'enforce_production_contract' "${POST_IMAGE}"
grep -q 'SUDERRA_INSTALLER_PAYLOAD_PUBKEY must point to the pinned Ed25519 public key' "${POST_IMAGE}"
grep -q 'openssl pkeyutl -verify -rawin -pubin' "${POST_IMAGE}"

grep -q 'BR2_PACKAGE_SUDERRA_VARIANT_PROD=y' "${POST_BUILD}"
grep -q 'BR2 Suderra variant.*conflicts with SUDERRA_VARIANT' "${POST_BUILD}"
grep -q 'requires BR2_CONFIG or SUDERRA_VARIANT' "${POST_BUILD}"
grep -q 'SUDERRA_VARIANT must be dev or prod' "${POST_BUILD}"

grep -q 'SUDERRA_SIGNING_MODE' "${SIGN_BUNDLE}"
grep -q 'SUDERRA_RELEASE_TIER' "${SIGN_BUNDLE}"
grep -q 'PROD_MODE' "${SIGN_BUNDLE}"
grep -q 'warn_or_fail' "${SIGN_BUNDLE}"
grep -q 'SUDERRA_RAUC_PKCS11_URI' "${SIGN_BUNDLE}"
grep -q 'production signing rejects file-backed private keys' "${SIGN_BUNDLE}"
