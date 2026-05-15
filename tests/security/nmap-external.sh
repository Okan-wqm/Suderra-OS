#!/usr/bin/env bash
#
# Nmap external port scan (Faz 3 placeholder)
#
# Hedef: 0 port görünmeli (production variant)
# Çalıştırma: cihazın IP'sine HOST machine'den

set -euo pipefail
IFS=$'\n\t'

TARGET="${1:-localhost}"

# TODO Faz 3:
# 1. nmap -sS -p- ${TARGET}
# 2. Parse output: "0 open"
# 3. UDP scan: nmap -sU -p 1-1000 ${TARGET}
# 4. IPv6 scan: nmap -6 ${TARGET}

echo "SKIP: Faz 3'te implement edilecek (hedef: 0 open port — TARGET=${TARGET})"
exit 77
