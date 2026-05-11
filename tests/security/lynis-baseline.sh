#!/usr/bin/env bash
#
# Lynis baseline tarama (Faz 3 placeholder)
#
# Hedef: Lynis skoru ≥ 85
# Çalıştırma: cihaz üzerinde veya QEMU içinde

set -euo pipefail
IFS=$'\n\t'

# TODO Faz 3:
# 1. QEMU'da Suderra OS boot et
# 2. ssh ile lynis paketini geçici yükle (sadece test ortamı)
# 3. lynis audit system çalıştır
# 4. Skor ≥ 85 kontrol et
# 5. /var/log/lynis-report.dat analiz

THRESHOLD=85

echo "SKIP: Faz 3'te implement edilecek (hedef skor ≥ ${THRESHOLD})"
exit 0
