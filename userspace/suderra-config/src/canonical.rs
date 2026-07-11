// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Kanonik JSON serileştirme — imza baytlarının TEK kaynağı.
//!
//! `suderra-installer` (USB payload index + edge manifest) ve `suderra-ota`
//! (OS update manifest) aynı imza-bayt sözleşmesini kullanır. Daha önce ota
//! `serde_json::to_vec` ile STRUCT ALAN SIRASINA bağlı bayt üretiyordu; alan
//! sırası değişse imza sessizce kırılırdı ve Python imzalayıcı ile eşleşme
//! tesadüfe kalmıştı. Bu modül installer'daki kanıtlanmış sorted-key formu
//! paylaşılan eve taşır (ADR-0008 §1'in öngördüğü çıkarma).
//!
//! Sözleşme (Python karşılığı: `json.dumps(payload, separators=(",", ":"),
//! sort_keys=True, ensure_ascii=False)`):
//! - Nesne anahtarları UTF-8 bayt sırasıyla (== Unicode code point sırası) sıralı
//! - Ayraçlarda boşluk yok (`,` ve `:`)
//! - String'ler `serde_json` kaçışıyla (kontrol karakterleri `\u00XX`, non-ASCII
//!   ham UTF-8) — Python `ensure_ascii=False` ile bayt-bayt aynı
//! - Sayılar: yalnız tam sayılar; float bu sözleşmede YASAK (imza baytlarında
//!   platforma bağlı formatlama riski). Şemalar float içermez.
//! - Üst-düzey `"signature"` anahtarı imza baytlarından çıkarılır
//!
//! Diller-arası eşitlik `tests/ota/fixtures/canonical-vectors/` altındaki golden
//! vektörlerle sınanır (Rust: bu modülün testleri; Python:
//! `tests/ota/canonicalization-crosslang-test.sh`).

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Değeri kanonik JSON baytlarına serileştir.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    canonical_value_bytes(&value)
}

/// Üst-düzey `"signature"` anahtarını çıkarıp kanonik baytları üret.
///
/// İmza alanı struct yerine JSON değerinden düşürülür; böylece `Option` +
/// `skip_serializing_if` gibi serde ayrıntılarına bağımlılık kalmaz.
pub fn canonical_without_signature<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    canonical_value_bytes(&value)
}

/// Ayrıştırılmış bir JSON değerinin kanonik baytları.
pub fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_canonical_value(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(value) => out.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            out.push('[');
            for (idx, value) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_value(value, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut first = true;
            for (key, value) in map.iter().collect::<BTreeMap<_, _>>() {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical_value(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn sorts_keys_and_stays_compact() {
        let value = json!({"b": 1, "a": {"z": [1, 2], "y": "s"}});
        let bytes = canonical_value_bytes(&value).unwrap();
        assert_eq!(bytes, br#"{"a":{"y":"s","z":[1,2]},"b":1}"#);
    }

    #[test]
    fn strips_top_level_signature_only() {
        let value = json!({"a": 1, "signature": {"x": 2}, "inner": {"signature": "kalır"}});
        let bytes = canonical_without_signature(&value).unwrap();
        // Non-ASCII ham UTF-8 kalır (Python ensure_ascii=False eşleniği).
        assert_eq!(bytes, r#"{"a":1,"inner":{"signature":"kalır"}}"#.as_bytes());
    }

    /// Golden vektörler: Python imzalayıcı ile bayt-bayt eşitliğin Rust yarısı.
    /// Python yarısı `tests/ota/canonicalization-crosslang-test.sh` içinde aynı
    /// committed `.canon` dosyalarına karşı koşar.
    #[test]
    fn golden_vectors_match_committed_canonical_bytes() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/ota/fixtures/canonical-vectors");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("vektör dizini okunmalı") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let input = std::fs::read_to_string(&path).unwrap();
            let value: Value = serde_json::from_str(&input).unwrap();
            let expected = std::fs::read(path.with_extension("canon")).unwrap();
            let actual = canonical_value_bytes(&value).unwrap();
            assert_eq!(
                actual,
                expected,
                "kanonik bayt uyuşmazlığı: {}",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 5, "en az 5 golden vektör bekleniyor: {checked}");
    }
}
