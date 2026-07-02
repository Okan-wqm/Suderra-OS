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

/// Normalize edilmiş bir varyant değeri üretim mi?
fn value_is_prod(value: &str) -> bool {
    let v = value.trim().trim_matches('"').trim_matches('\'').to_ascii_lowercase();
    v == "prod" || v == "production" || v.starts_with("prod-") || v.starts_with("prod_")
}

/// Cihaz/derleme bir Suderra OS üretim varyantı mı?
///
/// Sıra: açık env (`SUDERRA_OS_VARIANT` → `SUDERRA_VARIANT`) baskındır; yoksa
/// `/etc/os-release` içindeki `VARIANT`/`VARIANT_ID` alanına bakılır.
pub fn is_production() -> bool {
    for key in ["SUDERRA_OS_VARIANT", "SUDERRA_VARIANT"] {
        if let Ok(value) = std::env::var(key) {
            return value_is_prod(&value);
        }
    }

    let Ok(os_release) = std::fs::read_to_string("/etc/os-release") else {
        return false;
    };
    os_release.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(key, value)| matches!(key, "VARIANT" | "VARIANT_ID") && value_is_prod(value))
    })
}

#[cfg(test)]
mod tests {
    use super::value_is_prod;

    #[test]
    fn classifies_prod_labels() {
        for v in ["prod", "PROD", "\"prod\"", "production", "prod-eu", "prod_eu"] {
            assert!(value_is_prod(v), "{v} prod sayılmalı");
        }
    }

    #[test]
    fn rejects_non_prod_labels() {
        for v in ["dev", "lab", "", "staging", "preprod"] {
            assert!(!value_is_prod(v), "{v} prod SAYILMAMALI");
        }
    }
}
