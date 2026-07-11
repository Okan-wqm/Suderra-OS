// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Üretim (prod) varyant tespiti — TEK kaynak.
//!
//! Sözleşmenin kendisi (etiket sınıflandırması + imzalı `/etc/os-release` okuma)
//! `suderra_config::variant`'ta paylaşılır (ADR-0008 §1'in öngördüğü çıkarma;
//! `suderra-ota` aynı kökü kullanır). Burada yalnız installer'ın env ile
//! SIKILAŞTIRMA politikası kalır.
//!
//! GÜVEN KÖKÜ imzalı, salt-okunur `/etc/os-release`'tir. Orada üretim işaretli bir
//! cihazı hiçbir environment değişkeni non-prod yapamaz (downgrade engellenir);
//! env yalnızca sınıflandırmayı ÜRETİM yönünde sıkılaştırabilir. Ayrıca boş/yalnız
//! boşluk bir env değeri "ayarlanmamış" sayılır ki `SUDERRA_OS_VARIANT=` gibi bir
//! set-but-empty durumu fail-open ile prod'u dev'e çeviremesin.

use suderra_config::variant::{os_release_is_prod, value_is_prod};

/// Cihaz/derleme bir Suderra OS üretim varyantı mı?
///
/// Sıra: önce imzalı `/etc/os-release` (`VARIANT`/`VARIANT_ID`) — üretim diyorsa
/// sonuç kesin `true`'dur ve env ile GEVŞETİLEMEZ. os-release üretim demiyorsa
/// (dev/lab/CI-smoke ya da dosya yok) açık bir env yalnız ÜRETİM yönünde geçerlidir;
/// boş/whitespace env değeri yok sayılır.
pub fn is_production() -> bool {
    if os_release_is_prod() {
        return true;
    }
    for key in ["SUDERRA_OS_VARIANT", "SUDERRA_VARIANT"] {
        if let Ok(value) = std::env::var(key) {
            if value.trim().is_empty() {
                continue;
            }
            if value_is_prod(&value) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    // Not: test host'unun `/etc/os-release`'i üretim demediğinden `is_production`'ın
    // env yolu deterministik biçimde sınanır. os-release=prod iken env'in downgrade
    // EDEMEDİĞİ (asıl sertleştirme) yalnız gerçek prod imajında gözlemlenebilir.
    // Etiket sınıflandırma testleri paylaşılan `suderra_config::variant`'tadır.
    #[test]
    fn empty_env_is_ignored_and_env_only_tightens() {
        use super::is_production;
        std::env::remove_var("SUDERRA_OS_VARIANT");
        std::env::remove_var("SUDERRA_VARIANT");
        assert!(!is_production(), "env yok + host non-prod → prod olmamalı");

        // set-but-empty / whitespace: "ayarlanmamış" sayılır (fail-open yok).
        std::env::set_var("SUDERRA_OS_VARIANT", "");
        assert!(!is_production(), "boş env sınıflandırmayı değiştirmemeli");
        std::env::set_var("SUDERRA_OS_VARIANT", "   ");
        assert!(!is_production(), "whitespace env yok sayılmalı");

        // Env yalnız ÜRETİM yönünde geçerli.
        std::env::set_var("SUDERRA_OS_VARIANT", "prod");
        assert!(is_production(), "env=prod üretim saymalı");

        std::env::remove_var("SUDERRA_OS_VARIANT");
    }
}
