// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub const RELEASE_TAG_BINDING_SCHEMA: &str = "suderra.release-tag-binding.v1";
pub const OPERATOR_EVIDENCE_INGRESS_SCHEMA: &str = "suderra.operator-evidence-ingress.v1";
pub const AUDIT_LOG_SCHEMA: &str = "suderra.audit-log-snapshot.v1";
pub const STATION_REGISTRY_SCHEMA: &str = "suderra.lab-station-registry.v1";
pub const QEMU_SCHEMA: &str = "suderra.qemu-acceptance.v4";
pub const LAB_SCHEMA: &str = "suderra.lab-evidence.v3";
pub const APPROVAL_SCHEMA: &str = "suderra.release-approval.v2";
pub const REPRODUCIBILITY_SCHEMA: &str = "suderra.reproducibility.v1";

pub fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn validate_git_sha(value: &str, field: &str) -> Result<(), String> {
    if is_lower_hex(value, 40) {
        Ok(())
    } else {
        Err(format!("{field}: must be a lowercase git commit sha"))
    }
}

pub fn validate_sha256(value: &str, field: &str) -> Result<(), String> {
    if !is_lower_hex(value, 64) {
        return Err(format!("{field}: must be a lowercase sha256 digest"));
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err(format!("{field}: must not be the all-zero sha256 digest"));
    }
    Ok(())
}

pub fn positive_int_string(value: &Value, field: &str) -> Result<String, String> {
    match value {
        Value::String(raw) => parse_positive_int(raw, field),
        Value::Number(number) => {
            if let Some(raw) = number.as_u64() {
                if raw > 0 {
                    return Ok(raw.to_string());
                }
            }
            Err(format!("{field}: must be a positive integer"))
        }
        _ => Err(format!("{field}: must be a positive integer")),
    }
}

pub fn parse_positive_int(value: &str, field: &str) -> Result<String, String> {
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(format!("{field}: must be a positive integer"));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field}: must be a positive integer"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{field}: must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{field}: must be a positive integer"));
    }
    Ok(parsed.to_string())
}

pub fn require_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("$.{field}: must be a non-empty string"))
}

pub fn require_schema(object: &Map<String, Value>, expected: &str) -> Result<(), String> {
    match object.get("schema_version").and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(format!("$.schema_version: must be {expected}")),
    }
}

pub fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{path}: must be a JSON object"))
}

pub fn safe_rel_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.trim() != value || value.contains('\\') || value.contains('\0') {
        return Err("path must be a non-empty normalized relative path".to_string());
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err("path must be relative".to_string());
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| "path must be valid UTF-8".to_string())?;
                if part.is_empty() {
                    return Err("path components must be non-empty".to_string());
                }
                parts.push(part.to_string());
            }
            Component::ParentDir => return Err("path must not contain '..'".to_string()),
            Component::CurDir => return Err("path must not contain '.' components".to_string()),
            Component::RootDir | Component::Prefix(_) => {
                return Err("path must be relative".to_string())
            }
        }
    }
    if parts.is_empty() {
        return Err("path must contain at least one component".to_string());
    }
    Ok(parts.iter().collect())
}

pub fn path_role(rel: &Path) -> &'static str {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .collect();
    let top = parts.first().map(String::as_str);
    let name = parts.last().map(String::as_str);
    match (top, name) {
        (Some("release-governance"), Some("audit-log.json")) => "governance-audit-log",
        (Some("release-governance"), Some("station-registry.json")) => "station-registry",
        (Some("release-governance"), _) => "governance-input",
        (Some("release-approvals"), _) => "release-approval",
        (Some("release-reproducibility"), _) => "reproducibility-report",
        (Some("release-lab-input"), Some("qemu.json")) => "qemu-input",
        (Some("release-lab-input"), Some("lab.json")) => "lab-input",
        (Some("release-lab-input"), Some("station-bundle.json")) => "lab-station-bundle",
        (Some("release-lab-input"), Some("station-bundle.json.sig")) => "lab-station-signature",
        (Some("release-lab-input"), Some("station-public.pem")) => "lab-station-public-key",
        (Some("release-lab-input"), _) => "lab-supporting-evidence",
        _ => "operator-evidence",
    }
}

pub fn required_schema_for_path(rel: &Path) -> Option<&'static str> {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .collect();
    let top = parts.first().map(String::as_str);
    let name = parts.last().map(String::as_str);
    match (top, name) {
        (Some("release-governance"), Some("audit-log.json")) => Some(AUDIT_LOG_SCHEMA),
        (Some("release-governance"), Some("station-registry.json")) => {
            Some(STATION_REGISTRY_SCHEMA)
        }
        (Some("release-lab-input"), Some("qemu.json")) => Some(QEMU_SCHEMA),
        (Some("release-lab-input"), Some("lab.json")) => Some(LAB_SCHEMA),
        (Some("release-approvals"), _) => Some(APPROVAL_SCHEMA),
        (Some("release-reproducibility"), _) => Some(REPRODUCIBILITY_SCHEMA),
        _ => None,
    }
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_bytes(digest.finalize().as_ref()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub fn sorted_json_string(value: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&sort_value(value))
}

pub fn sorted_json_string_with_newline(value: &Value) -> Result<String, serde_json::Error> {
    let mut text = sorted_json_string(value)?;
    text.push('\n');
    Ok(text)
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&object[key]));
            }
            Value::Object(sorted)
        }
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_lowercase_hex_lengths() {
        assert!(is_lower_hex(&"a".repeat(40), 40));
        assert!(!is_lower_hex(&"A".repeat(40), 40));
        assert!(!is_lower_hex(&"g".repeat(40), 40));
        assert!(!is_lower_hex(&"a".repeat(39), 40));
    }

    #[test]
    fn rejects_zero_sha256() {
        assert!(validate_sha256(&"1".repeat(64), "$.sha256").is_ok());
        assert!(validate_sha256(&"0".repeat(64), "$.sha256").is_err());
    }

    #[test]
    fn normalizes_positive_integer_fields() {
        assert_eq!(positive_int_string(&json!("42"), "$.run_id").unwrap(), "42");
        assert_eq!(positive_int_string(&json!(42), "$.run_id").unwrap(), "42");
        assert!(positive_int_string(&json!("0"), "$.run_id").is_err());
        assert!(positive_int_string(&json!("-1"), "$.run_id").is_err());
        assert!(positive_int_string(&json!(1.5), "$.run_id").is_err());
    }

    #[test]
    fn rejects_unsafe_paths() {
        assert!(safe_rel_path("release-governance/v0/audit-log.json").is_ok());
        assert!(safe_rel_path("../audit-log.json").is_err());
        assert!(safe_rel_path("/tmp/audit-log.json").is_err());
        assert!(safe_rel_path("release\\audit-log.json").is_err());
        assert!(safe_rel_path("./audit-log.json").is_err());
    }

    #[test]
    fn keeps_json_keys_sorted_and_newline_terminated() {
        let value = json!({"z": 1, "a": {"b": 2, "a": 1}});
        let text = sorted_json_string_with_newline(&value).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.find("\"a\"").unwrap() < text.find("\"z\"").unwrap());
    }

    #[test]
    fn hashes_files_in_chunks() {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("suderra-schema-compat-{nonce}.txt"));
        fs::write(&path, b"abc").unwrap();
        let digest = sha256_file(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn encodes_hex_without_digest_format_traits() {
        assert_eq!(hex_bytes(&[0x00, 0xab, 0xff]), "00abff");
    }
}
