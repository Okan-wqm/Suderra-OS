// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Üretim (prod) varyant tespiti — TEK kaynak.
//!
//! Daha önce `download.rs` ve `cmd/install.rs` iki AYRI ve UYUŞMAYAN tanım
//! taşıyordu: biri yalnız `SUDERRA_VARIANT`'a bakıp exact `== "prod"` yapıyordu,
//! diğeri `SUDERRA_OS_VARIANT`/`VARIANT_ID`'yi case-insensitive kontrol ediyordu.
//! Sonuç: bir cihaz imza politikası için "prod", TLS politikası için "non-prod"
//! olabiliyordu. Ayrıca ikisi de exact eşleşme yaptığından `production`/`prod-eu`
//! gibi gerçek prod etiketleri yakalanmıyordu.
//!
//! Bu modül fail-safe davranır: değeri normalize edip **`prod` ile başlayan** her
//! varyantı üretim sayar (`prod`, `prod-eu`, `production`, ...). Over-classify
//! etmek güvenli yöndedir — kuşkulu durumda güvenlik gevşetmeleri (TLS-off,
//! imza-atlama, legacy-copy) bloklanır.
//!
//! GÜVEN KÖKÜ imzalı, salt-okunur `/etc/os-release`'tir. Orada üretim işaretli bir
//! cihazı hiçbir environment değişkeni non-prod yapamaz (downgrade engellenir);
//! env yalnızca sınıflandırmayı ÜRETİM yönünde sıkılaştırabilir. Ayrıca boş/yalnız
//! boşluk bir env değeri "ayarlanmamış" sayılır ki `SUDERRA_OS_VARIANT=` gibi bir
//! set-but-empty durumu fail-open ile prod'u dev'e çeviremesin.

/// Normalize edilmiş bir varyant değeri üretim mi?
fn value_is_prod(value: &str) -> bool {
    let v = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    v == "prod" || v == "production" || v.starts_with("prod-") || v.starts_with("prod_")
}

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

/// İmzalı, salt-okunur `/etc/os-release` cihazı üretim olarak işaretliyor mu?
fn os_release_is_prod() -> bool {
    let Ok(os_release) = std::fs::read_to_string("/etc/os-release") else {
        return false;
    };
    os_release.lines().any(|line| {
        line.split_once('=').is_some_and(|(key, value)| {
            matches!(key, "VARIANT" | "VARIANT_ID") && value_is_prod(value)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::value_is_prod;

    #[test]
    fn classifies_prod_labels() {
        for v in [
            "prod",
            "PROD",
            "\"prod\"",
            "production",
            "prod-eu",
            "prod_eu",
        ] {
            assert!(value_is_prod(v), "{v} prod sayılmalı");
        }
    }

    #[test]
    fn rejects_non_prod_labels() {
        for v in ["dev", "lab", "", "staging", "preprod"] {
            assert!(!value_is_prod(v), "{v} prod SAYILMAMALI");
        }
    }

    // Not: test host'unun `/etc/os-release`'i üretim demediğinden `is_production`'ın
    // env yolu deterministik biçimde sınanır. os-release=prod iken env'in downgrade
    // EDEMEDİĞİ (asıl sertleştirme) yalnız gerçek prod imajında gözlemlenebilir.
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
