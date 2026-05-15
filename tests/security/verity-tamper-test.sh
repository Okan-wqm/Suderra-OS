#!/usr/bin/env bash
#
# dm-verity tampering testi (Faz 3 placeholder)
#
# Hedef: rootfs imajına 1 byte değiştirilirse kernel reddetmeli

set -euo pipefail
IFS=$'\n\t'

# TODO Faz 3:
# 1. Sağlam disk.img kopyala
# 2. Belirli offset'te 1 byte XOR ile değiştir
# 3. QEMU'da boot dene
# 4. Beklenen: "dm-verity: verification failed" mesajı + sistem durması
# 5. Sağlam imajla doğrula: normal boot

echo "SKIP: Faz 3'te implement edilecek"
exit 77
