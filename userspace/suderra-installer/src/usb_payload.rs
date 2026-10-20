// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Signed universal USB installer payload index (OS installation and
//! recovery, ADR-048 DEC-2.2 path 6).
//!
//! The Suderra edge contract verifier lives in `contracts`; the flat
//! `suderra.edge-provisioning.v1` manifest this file used to verify was
//! never produced and is removed with its re-serializing verifier
//! (contracts statements.json `superseded_formats`, DEC-3.2, EI-054).

use crate::cli::{UsbPayloadArgs, UsbPayloadCommand, UsbPayloadSignArgs, UsbPayloadVerifyArgs};
use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const USB_INDEX_KIND: &str = "suderra.usb-payload-index.v1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub(crate) fn run_usb_payload(args: UsbPayloadArgs) -> Result<()> {
    match args.command {
        UsbPayloadCommand::Verify(args) => {
            let validated = verify_usb_payload(&args)?;
            if let Some(path) = args.write_plan.as_deref() {
                write_usb_plan(path, &validated)?;
            } else {
                println!("{}", validated.image_path.display());
            }
            Ok(())
        }
        UsbPayloadCommand::Sign(args) => sign_json_with_openssl_ed25519(&args),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsbPayloadIndex {
    schema_version: u32,
    kind: String,
    board_family: String,
    compatible_models: Vec<String>,
    payloads: Vec<UsbImagePayload>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    key_epoch: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsbImagePayload {
    name: String,
    board_family: String,
    compatible_models: Vec<String>,
    arch: String,
    image_path: String,
    compressed_sha256: String,
    compressed_size_bytes: u64,
    uncompressed_sha256: String,
    uncompressed_size_bytes: u64,
    min_storage_bytes: u64,
    #[serde(default)]
    rollback_floor: Option<String>,
}

#[derive(Debug)]
struct ValidatedUsbPayload {
    index: UsbPayloadIndex,
    payload: UsbImagePayload,
    image_path: PathBuf,
}

fn verify_usb_payload(args: &UsbPayloadVerifyArgs) -> Result<ValidatedUsbPayload> {
    let payload_dir = &args.payload_dir;
    let manifest_path = payload_dir.join("manifest.json");
    let signature_path = payload_dir.join("manifest.sig");
    let manifest_bytes = fs::read(&manifest_path)
        .with_context(|| format!("USB payload manifest missing: {}", manifest_path.display()))?;
    let index: UsbPayloadIndex =
        serde_json::from_slice(&manifest_bytes).context("USB payload manifest JSON is invalid")?;

    ensure_schema(index.schema_version, &index.kind, USB_INDEX_KIND)?;
    let canonical = canonical_json_bytes(&index)?;
    let sig = read_signature(&signature_path)?;
    let key = read_public_key(&args.public_key)?;
    verify_ed25519(&key, &canonical, &sig).with_context(|| {
        format!(
            "USB payload manifest signature verification failed: {}",
            manifest_path.display()
        )
    })?;

    ensure_not_expired(index.expires_at, "USB payload manifest")?;
    ensure_key_epoch_at_least(index.key_epoch, args.min_key_epoch, "USB payload manifest")?;
    ensure_nonempty("board_family", &index.board_family)?;
    ensure_nonempty_vec("compatible_models", &index.compatible_models)?;
    ensure_nonempty_vec("payloads", &index.payloads)?;
    if !index
        .compatible_models
        .iter()
        .any(|model| model == &args.target_board)
    {
        bail!(
            "target board '{}' is not compatible with USB payload index '{}'",
            args.target_board,
            index.board_family
        );
    }

    let payload = index
        .payloads
        .iter()
        .find(|payload| {
            payload.board_family == args.target_board
                || payload
                    .compatible_models
                    .iter()
                    .any(|model| model == &args.target_board)
        })
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no payload entry matches target board '{}'",
                args.target_board
            )
        })?;

    validate_payload_metadata(&payload)?;
    if payload.arch != args.target_arch {
        bail!(
            "payload arch '{}' does not match target arch '{}'",
            payload.arch,
            args.target_arch
        );
    }
    ensure_rollback_floor_at_least(&payload, &args.min_rollback_floor)?;
    let image_path = safe_join(payload_dir, &payload.image_path)?;
    verify_file_size(
        &image_path,
        payload.compressed_size_bytes,
        "compressed payload",
    )?;
    verify_file_sha256(
        &image_path,
        &payload.compressed_sha256,
        "compressed payload",
    )?;
    verify_xz_uncompressed(&image_path, &payload)?;

    Ok(ValidatedUsbPayload {
        index,
        payload,
        image_path,
    })
}

fn sign_json_with_openssl_ed25519(args: &UsbPayloadSignArgs) -> Result<()> {
    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("manifest not readable: {}", args.manifest.display()))?;
    let index: UsbPayloadIndex =
        serde_json::from_slice(&manifest_bytes).context("USB payload manifest JSON invalid")?;
    let canonical = canonical_json_bytes(&index)?;

    let mut canonical_file = tempfile::NamedTempFile::new()?;
    canonical_file.write_all(&canonical)?;
    canonical_file.flush()?;

    let output = Command::new("openssl")
        .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
        .arg(&args.private_key)
        .arg("-in")
        .arg(canonical_file.path())
        .arg("-out")
        .arg(&args.signature)
        .output()
        .context("openssl pkeyutl could not be started")?;
    if !output.status.success() {
        bail!(
            "openssl Ed25519 signing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn write_usb_plan(path: &Path, validated: &ValidatedUsbPayload) -> Result<()> {
    let mut vars = BTreeMap::new();
    vars.insert(
        "SUDERRA_PAYLOAD_INDEX_BOARD_FAMILY",
        validated.index.board_family.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_BOARD_FAMILY",
        validated.payload.board_family.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_IMAGE_PATH",
        validated.image_path.display().to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_IMAGE_NAME",
        validated.payload.image_path.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_COMPRESSED_SHA256",
        validated.payload.compressed_sha256.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_COMPRESSED_SIZE_BYTES",
        validated.payload.compressed_size_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_UNCOMPRESSED_SHA256",
        validated.payload.uncompressed_sha256.clone(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_UNCOMPRESSED_SIZE_BYTES",
        validated.payload.uncompressed_size_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_MIN_STORAGE_BYTES",
        validated.payload.min_storage_bytes.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_KEY_EPOCH",
        validated.index.key_epoch.to_string(),
    );
    vars.insert(
        "SUDERRA_PAYLOAD_EXPIRES_AT",
        validated.index.expires_at.to_rfc3339(),
    );
    if let Some(rollback_floor) = &validated.payload.rollback_floor {
        vars.insert("SUDERRA_PAYLOAD_ROLLBACK_FLOOR", rollback_floor.clone());
    }
    write_shell_env(path, &vars)
}

fn write_shell_env(path: &Path, vars: &BTreeMap<&str, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = String::new();
    for (key, value) in vars {
        content.push_str(key);
        content.push('=');
        content.push_str(&shell_quote(value));
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn ensure_schema(version: u32, kind: &str, expected_kind: &str) -> Result<()> {
    if version != 1 {
        bail!("unsupported schema_version: {version}");
    }
    if kind != expected_kind {
        bail!("unsupported manifest kind: {kind}");
    }
    Ok(())
}

fn ensure_not_expired(expires_at: DateTime<Utc>, label: &str) -> Result<()> {
    if Utc::now() > expires_at {
        bail!("{label} expired at {expires_at}");
    }
    Ok(())
}

fn ensure_key_epoch_at_least(actual: u32, minimum: u32, label: &str) -> Result<()> {
    if actual < minimum {
        bail!("{label} key_epoch {actual} is below required epoch {minimum}");
    }
    Ok(())
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} is required");
    }
    Ok(())
}

fn ensure_nonempty_vec<T>(field: &str, value: &[T]) -> Result<()> {
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn validate_payload_metadata(payload: &UsbImagePayload) -> Result<()> {
    ensure_nonempty("payload.name", &payload.name)?;
    ensure_nonempty("payload.board_family", &payload.board_family)?;
    ensure_nonempty_vec("payload.compatible_models", &payload.compatible_models)?;
    ensure_nonempty("payload.arch", &payload.arch)?;
    ensure_nonempty("payload.image_path", &payload.image_path)?;
    ensure_sha256(&payload.compressed_sha256, "payload.compressed_sha256")?;
    ensure_sha256(&payload.uncompressed_sha256, "payload.uncompressed_sha256")?;
    if payload.compressed_size_bytes == 0 {
        bail!("payload.compressed_size_bytes must be greater than zero");
    }
    if payload.uncompressed_size_bytes == 0 {
        bail!("payload.uncompressed_size_bytes must be greater than zero");
    }
    if payload.min_storage_bytes < payload.uncompressed_size_bytes {
        bail!("payload.min_storage_bytes is smaller than the image");
    }
    Ok(())
}

fn ensure_rollback_floor_at_least(payload: &UsbImagePayload, required_floor: &str) -> Result<()> {
    let floor = payload
        .rollback_floor
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("payload.rollback_floor is required"))?;
    ensure_nonempty("payload.rollback_floor", floor)?;
    ensure_version_floor_at_least(floor, required_floor, "payload.rollback_floor")
}

fn ensure_version_floor_at_least(actual: &str, required: &str, label: &str) -> Result<()> {
    ensure_nonempty(label, actual)?;
    ensure_nonempty("required rollback floor", required)?;
    if compare_versions(actual, required).with_context(|| {
        format!("could not compare {label} '{actual}' with required floor '{required}'")
    })? == std::cmp::Ordering::Less
    {
        bail!("{label} {actual} is below required floor {required}");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedVersion<'a> {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<&'a str>,
}

fn compare_versions(left: &str, right: &str) -> Result<std::cmp::Ordering> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Ok(left
        .major
        .cmp(&right.major)
        .then(left.minor.cmp(&right.minor))
        .then(left.patch.cmp(&right.patch))
        .then_with(|| compare_prerelease(left.pre, right.pre)))
}

fn parse_version(value: &str) -> Result<ParsedVersion<'_>> {
    let value = value.trim().trim_start_matches('v');
    let (core, pre) = value.split_once('-').unwrap_or((value, ""));
    let mut parts = core.split('.');
    let major = parse_version_part(parts.next(), value)?;
    let minor = parse_version_part(parts.next(), value)?;
    let patch = parse_version_part(parts.next(), value)?;
    if parts.next().is_some() {
        bail!("version has too many numeric components: {value}");
    }
    Ok(ParsedVersion {
        major,
        minor,
        patch,
        pre: if pre.is_empty() { None } else { Some(pre) },
    })
}

fn parse_version_part(part: Option<&str>, value: &str) -> Result<u64> {
    part.filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("version must use major.minor.patch form: {value}"))?
        .parse()
        .with_context(|| format!("version contains a non-numeric component: {value}"))
}

fn compare_prerelease(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    match (left, right) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(left), Some(right)) => compare_prerelease_segments(left, right),
    }
}

fn compare_prerelease_segments(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                let ord = match (left.parse::<u64>(), right.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => left.cmp(right),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn ensure_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must be a 64-character hex SHA256 digest");
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute() {
        bail!("manifest image_path must be relative");
    }
    let mut joined = PathBuf::from(root);
    for component in path.components() {
        match component {
            Component::Normal(part) => joined.push(part),
            _ => bail!("manifest image_path contains unsafe component: {relative}"),
        }
    }
    Ok(joined)
}

fn verify_file_size(path: &Path, expected: u64, label: &str) -> Result<()> {
    let actual = fs::metadata(path)
        .with_context(|| format!("{label} not readable: {}", path.display()))?
        .len();
    if actual != expected {
        bail!("{label} size mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_file_sha256(path: &Path, expected: &str, label: &str) -> Result<()> {
    let actual = sha256_file(path)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("{label} SHA256 mismatch");
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("file not readable: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn verify_xz_uncompressed(path: &Path, payload: &UsbImagePayload) -> Result<()> {
    let mut child = Command::new("xz")
        .arg("-dc")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("xz could not decompress {}", path.display()))?;
    let mut stdout = child.stdout.take().context("xz stdout unavailable")?;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = stdout.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        hasher.update(&buffer[..read]);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "xz payload decompression failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if count != payload.uncompressed_size_bytes {
        bail!(
            "uncompressed payload size mismatch: expected {}, got {}",
            payload.uncompressed_size_bytes,
            count
        );
    }
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(&payload.uncompressed_sha256) {
        bail!("uncompressed payload SHA256 mismatch");
    }
    Ok(())
}

fn read_public_key(path: &Path) -> Result<VerifyingKey> {
    let bytes =
        fs::read(path).with_context(|| format!("public key not readable: {}", path.display()))?;
    let raw = if bytes.starts_with(b"-----BEGIN PUBLIC KEY-----") {
        parse_ed25519_public_key_pem(&bytes)?
    } else {
        decode_hex_array::<32>(std::str::from_utf8(&bytes)?.trim(), "public key")?
    };
    VerifyingKey::from_bytes(&raw).context("invalid Ed25519 public key")
}

fn parse_ed25519_public_key_pem(bytes: &[u8]) -> Result<[u8; 32]> {
    let text = std::str::from_utf8(bytes).context("public key PEM is not UTF-8")?;
    let b64: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("public key PEM base64 decode failed")?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        bail!("public key PEM is not an Ed25519 SubjectPublicKeyInfo");
    }
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(&der[ED25519_SPKI_PREFIX.len()..]);
    Ok(raw)
}

fn read_signature(path: &Path) -> Result<Signature> {
    let bytes =
        fs::read(path).with_context(|| format!("signature not readable: {}", path.display()))?;
    decode_signature_bytes(&bytes)
}

fn decode_signature_bytes(bytes: &[u8]) -> Result<Signature> {
    if bytes.len() == 64 {
        let mut raw = [0_u8; 64];
        raw.copy_from_slice(bytes);
        return Ok(Signature::from_bytes(&raw));
    }
    let text = std::str::from_utf8(bytes)
        .context("signature must be raw 64 bytes or hex text")?
        .trim();
    let raw = decode_hex_array::<64>(text, "signature")?;
    Ok(Signature::from_bytes(&raw))
}

fn decode_hex_array<const N: usize>(text: &str, label: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(text).with_context(|| format!("{label} is not valid hex"))?;
    if decoded.len() != N {
        bail!("{label} must decode to {N} bytes");
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn verify_ed25519(key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    key.verify(message, signature).map_err(Into::into)
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    canonical_value_bytes(&value)
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>> {
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
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        (key, public)
    }

    fn write_xz_payload(dir: &Path) -> (String, u64, String, u64) {
        let raw = b"suderra target image bytes";
        let raw_path = dir.join("target.img");
        let xz_path = dir.join("suderra-rpi4-target.img.xz");
        fs::write(&raw_path, raw).unwrap();
        let status = Command::new("xz")
            .args(["-z", "-k", "-f"])
            .arg(&raw_path)
            .status()
            .unwrap();
        assert!(status.success());
        fs::rename(dir.join("target.img.xz"), &xz_path).unwrap();
        let compressed_sha = sha256_file(&xz_path).unwrap();
        let compressed_size = fs::metadata(&xz_path).unwrap().len();
        let uncompressed_sha = sha256_bytes(raw);
        let uncompressed_size = raw.len() as u64;
        (
            compressed_sha,
            compressed_size,
            uncompressed_sha,
            uncompressed_size,
        )
    }

    fn usb_index(
        compressed_sha: String,
        compressed_size: u64,
        uncompressed_sha: String,
        uncompressed_size: u64,
    ) -> UsbPayloadIndex {
        UsbPayloadIndex {
            schema_version: 1,
            kind: USB_INDEX_KIND.into(),
            board_family: "pi-cm4-revpi".into(),
            compatible_models: vec!["rpi4-cm4".into(), "revpi4".into()],
            payloads: vec![UsbImagePayload {
                name: "rpi4".into(),
                board_family: "rpi4-cm4".into(),
                compatible_models: vec!["rpi4-cm4".into()],
                arch: "aarch64".into(),
                image_path: "suderra-rpi4-target.img.xz".into(),
                compressed_sha256: compressed_sha,
                compressed_size_bytes: compressed_size,
                uncompressed_sha256: uncompressed_sha,
                uncompressed_size_bytes: uncompressed_size,
                min_storage_bytes: 8 * 1024 * 1024 * 1024,
                rollback_floor: Some("v0.1.0-alpha".into()),
            }],
            created_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: "2099-01-01T00:00:00Z".parse().unwrap(),
            key_epoch: 1,
        }
    }

    fn sign_usb_index(dir: &Path, index: &UsbPayloadIndex, key: &SigningKey, public: &str) {
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(index).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("payload.pub"), public).unwrap();
        let canonical = canonical_json_bytes(index).unwrap();
        let sig = key.sign(&canonical);
        fs::write(dir.join("manifest.sig"), hex::encode(sig.to_bytes())).unwrap();
    }

    fn usb_verify_args(dir: &Path, target_board: &str) -> UsbPayloadVerifyArgs {
        UsbPayloadVerifyArgs {
            payload_dir: dir.into(),
            public_key: dir.join("payload.pub"),
            target_board: target_board.into(),
            target_arch: "aarch64".into(),
            min_key_epoch: 1,
            min_rollback_floor: "v0.1.0-alpha".into(),
            write_plan: None,
        }
    }

    #[test]
    fn usb_payload_verifies_and_writes_plan() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let plan = tmp.path().join("plan.env");
        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.write_plan = Some(plan.clone());
        let result = verify_usb_payload(&args).unwrap();
        assert_eq!(result.payload.board_family, "rpi4-cm4");
        write_usb_plan(&plan, &result).unwrap();
        let plan_text = fs::read_to_string(plan).unwrap();
        assert!(plan_text.contains("SUDERRA_PAYLOAD_IMAGE_PATH="));
    }

    #[test]
    fn usb_payload_rejects_board_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "unknown-board")).unwrap_err();
        assert!(err.to_string().contains("not compatible"));
    }

    #[test]
    fn usb_payload_rejects_expired_index() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        index.expires_at = "2000-01-01T00:00:00Z".parse().unwrap();
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn usb_payload_rejects_key_epoch_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.min_key_epoch = 2;
        let err = verify_usb_payload(&args).unwrap_err();
        assert!(err.to_string().contains("below required epoch"));
    }

    #[test]
    fn usb_payload_rejects_rollback_floor() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);

        let mut args = usb_verify_args(tmp.path(), "rpi4-cm4");
        args.min_rollback_floor = "v0.2.0".into();
        let err = verify_usb_payload(&args).unwrap_err();
        assert!(err.to_string().contains("below required floor"));
    }

    #[test]
    fn usb_payload_rejects_path_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        index.payloads[0].image_path = "../target.img.xz".into();
        sign_usb_index(tmp.path(), &index, &key, &public);

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(err.to_string().contains("unsafe component"));
    }

    #[test]
    fn usb_payload_rejects_wrong_signature() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (key, public) = keypair();
        let (c_sha, c_size, u_sha, u_size) = write_xz_payload(tmp.path());
        let mut index = usb_index(c_sha, c_size, u_sha, u_size);
        sign_usb_index(tmp.path(), &index, &key, &public);
        index.key_epoch = 2;
        fs::write(
            tmp.path().join("manifest.json"),
            serde_json::to_string_pretty(&index).unwrap(),
        )
        .unwrap();

        let err = verify_usb_payload(&usb_verify_args(tmp.path(), "rpi4-cm4")).unwrap_err();
        assert!(format!("{err:#}").contains("signature verification failed"));
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value: Value = serde_json::from_str(r#"{"b":2,"a":{"d":4,"c":3}}"#).unwrap();
        let canonical = String::from_utf8(canonical_value_bytes(&value).unwrap()).unwrap();
        assert_eq!(canonical, r#"{"a":{"c":3,"d":4},"b":2}"#);
    }
}
