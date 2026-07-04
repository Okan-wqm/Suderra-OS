# Suderra OS — U-Boot boot script (ADR-0007, RAUC A/B + signed FIT)
#
# mkimage -A arm64 -T script -C none -d boot.scr.cmd boot.scr ile derlenir
# (post-image, PR-A6). Pi firmware config.txt (kernel=u-boot.bin) ile U-Boot'u
# yükler; U-Boot bu script'i boot FAT bölümünden çalıştırır.
#
# RAUC U-Boot backend'i (package/suderra-rauc-config, PR-A5) BOOT_ORDER +
# BOOT_<slot>_LEFT ortam değişkenlerini yönetir. Bu script sıradaki bootable
# slotu seçer, deneme sayacını azaltır ve İMZALI FIT'i bootm ile boot eder.
# CONFIG_FIT_SIGNATURE (uboot-fragment) bootm sırasında FIT imzasını ZORUNLU
# doğrular; imzasız/kurcalanmış FIT reddedilir. Kernel+DTB+initramfs+bootargs
# (rauc.slot dahil) imzalı FIT içindedir.

setenv fitaddr 0x02000000

# İlk boot / bozuk env için güvenli varsayılanlar.
if test -z "${BOOT_ORDER}"; then setenv BOOT_ORDER "A B"; fi
if test -z "${BOOT_A_LEFT}"; then setenv BOOT_A_LEFT 3; fi
if test -z "${BOOT_B_LEFT}"; then setenv BOOT_B_LEFT 3; fi

setenv bootslot ""
for slot in ${BOOT_ORDER}; do
  if test "${bootslot}" = ""; then
    if test "${slot}" = "A"; then
      if test ${BOOT_A_LEFT} -gt 0; then
        setexpr BOOT_A_LEFT ${BOOT_A_LEFT} - 1
        saveenv
        setenv bootslot A
      fi
    fi
    if test "${slot}" = "B"; then
      if test ${BOOT_B_LEFT} -gt 0; then
        setexpr BOOT_B_LEFT ${BOOT_B_LEFT} - 1
        saveenv
        setenv bootslot B
      fi
    fi
  fi
done

if test "${bootslot}" = ""; then
  echo "Suderra: no bootable slot left (BOOT_ORDER=${BOOT_ORDER})"
  reset
fi

echo "Suderra: booting slot ${bootslot} (signed FIT enforced)"
if load mmc 0:1 ${fitaddr} suderra-${bootslot}.fit; then
  bootm ${fitaddr}
fi

echo "Suderra: slot ${bootslot} FIT load/verify failed"
reset
