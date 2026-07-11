// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Üretim (prod) varyant tespitinin GÜVEN KÖKÜ — paylaşılan sözleşme.
//!
//! `suderra-installer` ve `suderra-ota` daha önce aynı sözleşmenin iki kopyasını
//! taşıyordu (ADR-0008 §1: "paylaşılan modüle çıkarılır"). Bu modül tek kaynaktır:
//! - [`value_is_prod`] — normalize edilmiş varyant etiketi sınıflandırması
//! - [`os_release_variant`] / [`os_release_is_prod`] — imzalı, dm-verity altındaki
//!   salt-okunur `/etc/os-release`'ten okuma
//!
//! Env ile SIKILAŞTIRMA politikası (hangi değişken, hangi semantik) bilinçli olarak
//! tüketici crate'te kalır: installer `SUDERRA_OS_VARIANT`/`SUDERRA_VARIANT`
//! değerlerini, ota `SUDERRA_OTA_PRODUCTION=1`'i kabul eder. Ortak invariant her
//! iki tarafta aynıdır: os-release üretim diyorsa hiçbir env bunu GEVŞETEMEZ.

/// Normalize edilmiş bir varyant değeri üretim mi?
///
/// Fail-safe: `prod` ile başlayan her etiket üretim sayılır (`prod`, `prod-eu`,
/// `production`). Over-classify güvenli yöndedir — kuşkulu durumda güvenlik
/// gevşetmeleri bloklanır.
pub fn value_is_prod(value: &str) -> bool {
    let v = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    v == "prod" || v == "production" || v.starts_with("prod-") || v.starts_with("prod_")
}

/// İmzalı `/etc/os-release`'ten `VARIANT`/`VARIANT_ID` değerini okur.
pub fn os_release_variant() -> Option<String> {
    os_release_variant_from(&std::fs::read_to_string("/etc/os-release").ok()?)
}

/// `/etc/os-release` içeriğinden `VARIANT`/`VARIANT_ID` değerini ayıklar.
/// (Test edilebilirlik için içerik parametreli; cihazda [`os_release_variant`].)
pub fn os_release_variant_from(content: &str) -> Option<String> {
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if matches!(key, "VARIANT" | "VARIANT_ID") {
                let v = value.trim().trim_matches('"').trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// İmzalı, salt-okunur `/etc/os-release` cihazı üretim olarak işaretliyor mu?
pub fn os_release_is_prod() -> bool {
    os_release_variant().is_some_and(|v| value_is_prod(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parses_variant_from_os_release_content() {
        let content = "NAME=\"Suderra OS\"\nVARIANT=\"prod\"\nVERSION_ID=1.2.3\n";
        assert_eq!(os_release_variant_from(content).as_deref(), Some("prod"));
        assert_eq!(os_release_variant_from("NAME=x\n"), None);
        // set-but-empty değer "yok" sayılır (fail-open değil).
        assert_eq!(os_release_variant_from("VARIANT=\"\"\n"), None);
    }
}
