#!/usr/bin/env bash
#
# No local kiosk on Suderra OS (ADR-048 DEC-26).
#
# sens-api-gateway/systemd/suderra-display.service (cage + chromium) belongs
# to the generic-Linux channel only. No Suderra OS image ships it, a kiosk
# compositor or a browser; the HMI is served over the LAN, per site, with TLS
# and authentication.
#
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

while IFS= read -r unit; do
    fail "kiosk unit in the image tree: ${unit#"${ROOT}/"}"
done < <(find "${ROOT}/board" "${ROOT}/package" -name 'suderra-display*' -not -path '*/buildroot/*')

if grep -R -n 'suderra-display' "${ROOT}/board" "${ROOT}/package" "${ROOT}/configs"; then
    fail "no image source may reference suderra-display (DEC-26)"
fi

# Kiosk compositors, browsers and display servers stay out of every image.
kiosk_symbols='^BR2_PACKAGE_(CAGE|WESTON|SWAY|LABWC|COG|WPEWEBKIT|WEBKITGTK|CHROMIUM[A-Z_]*|FIREFOX|QT5WEBENGINE|QT6WEBENGINE|XORG7|XSERVER_XORG_SERVER|XAPP_[A-Z_]*)=y'
if grep -n -E "${kiosk_symbols}" "${ROOT}"/configs/*_defconfig; then
    fail "a defconfig enables a kiosk compositor, browser or display server (DEC-26)"
fi

echo "no-kiosk contract passed"
