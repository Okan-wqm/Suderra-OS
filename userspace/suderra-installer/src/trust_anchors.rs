// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Pinned keys and the trust-anchor bundle (ADR-048 DEC-3.3, DEC-3.4,
//! DEC-3.7, DEC-3.9).
//!
//! Root verifies edge-release, edge-provisioning, trust-anchors and
//! device-lifecycle statements only against keys pinned in the OS image
//! (`/etc/suderra/keys/<purpose>/<epoch>.pub`), and site-config and RBAC
//! statements against the anchors of a bundle that verified against the
//! pinned fleet-root. The loader refuses every contract TEST-ONLY key in
//! every variant, and on production images every key outside the
//! production keyid allowlist.

use crate::contracts::encoding::sha256_hex;
use crate::contracts::keys::{KeyEntry, KeyStore};
use crate::contracts::registry::{Purpose, TEST_ONLY_KEYIDS};
use crate::fsutil::read_root_file;
use crate::paths::Paths;
use crate::variant::Variant;
use anyhow::{bail, Context, Result};
use base64::Engine;

/// Production keyids by (purpose, epoch, keyid), from the P1 key ceremony
/// recorded in docs/security/key-management.md (DEC-3.9). Until that
/// ceremony runs no production key exists, so a production image refuses
/// every pin and provisions nothing; dev and QEMU images pin dev/CI keys.
pub(crate) const PRODUCTION_KEYIDS: &[(Purpose, u16, &str)] = &[];

/// DER prefix of an Ed25519 SubjectPublicKeyInfo.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Raw key of a PEM Ed25519 SubjectPublicKeyInfo.
pub(crate) fn parse_spki_pem(text: &str) -> Result<[u8; 32]> {
    let body = text
        .trim_end()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|r| r.strip_suffix("-----END PUBLIC KEY-----"))
        .context("not a PEM PUBLIC KEY block")?;
    let b64: String = body.split_whitespace().collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("PEM body is not base64")?;
    let raw = der
        .strip_prefix(&ED25519_SPKI_PREFIX[..])
        .context("not an Ed25519 SubjectPublicKeyInfo")?;
    raw.try_into().context("Ed25519 key is not 32 bytes")
}

fn parse_epoch(name: &str) -> Option<u16> {
    let digits = name.strip_suffix(".pub")?;
    let ok = match digits.as_bytes() {
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if ok {
        digits.parse().ok()
    } else {
        None
    }
}

/// Admits one pinned key under the variant's policy.
pub(crate) fn admit(entry: &KeyEntry, variant: Variant) -> Result<()> {
    let keyid = sha256_hex(&entry.raw);
    if TEST_ONLY_KEYIDS.contains(&keyid.as_str()) {
        bail!(
            "{}/{} pins contract TEST-ONLY key {keyid}; no image may pin it (DEC-3.9)",
            entry.purpose,
            entry.epoch
        );
    }
    if variant == Variant::Production
        && !PRODUCTION_KEYIDS
            .iter()
            .any(|(p, e, k)| *p == entry.purpose && *e == entry.epoch && *k == keyid)
    {
        bail!(
            "{}/{} key {keyid} is not on the production keyid allowlist (DEC-3.9)",
            entry.purpose,
            entry.epoch
        );
    }
    Ok(())
}

/// Loads every key pinned in the OS image for the os-image purposes.
pub(crate) fn load_os_pins(paths: &Paths, variant: Variant) -> Result<KeyStore> {
    let mut entries = Vec::new();
    for purpose in Purpose::ALL
        .iter()
        .copied()
        .filter(|p| p.anchored_in_os_image())
    {
        let dir = paths.key_pins().join(purpose.as_str());
        let listing = match std::fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("cannot list {}", dir.display())),
        };
        for item in listing {
            let item = item?;
            let name = item.file_name();
            let name = name.to_str().context("non-UTF-8 key file name")?;
            let epoch = parse_epoch(name)
                .with_context(|| format!("{}: not <epoch>.pub", dir.join(name).display()))?;
            let path = dir.join(name);
            let bytes = read_root_file(&path, 4096)?
                .with_context(|| format!("{} vanished", path.display()))?;
            let text = String::from_utf8(bytes).context("key file is not UTF-8")?;
            let entry = KeyEntry {
                purpose,
                epoch,
                raw: parse_spki_pem(&text).with_context(|| path.display().to_string())?,
            };
            admit(&entry, variant)?;
            entries.push(entry);
        }
    }
    KeyStore::from_entries(entries).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{pin_key, signing_key};

    #[test]
    fn pins_load_by_purpose_and_epoch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = Paths::under(tmp.path());
        let release = signing_key("edge-release");
        pin_key(&paths, Purpose::EdgeRelease, 1, &release);
        pin_key(&paths, Purpose::FleetRoot, 3, &signing_key("fleet"));
        let store = load_os_pins(&paths, Variant::Dev).unwrap();
        assert_eq!(store.len(), 2);
        let keyid = sha256_hex(release.verifying_key().as_bytes());
        let entry = store.get(&keyid).unwrap();
        assert_eq!((entry.purpose, entry.epoch), (Purpose::EdgeRelease, 1));
    }

    #[test]
    fn test_only_keys_are_refused_in_every_variant() {
        let ring: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../contracts/suderra-edge/v1/test-keys/keyring.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let first = &ring["keys"][0];
        let raw = crate::contracts::encoding::decode_base64_array::<32>(
            first["public_key"].as_str().unwrap(),
        )
        .unwrap();
        let entry = KeyEntry {
            purpose: Purpose::parse(first["purpose"].as_str().unwrap()).unwrap(),
            epoch: 1,
            raw,
        };
        for variant in [Variant::Dev, Variant::Production] {
            let err = admit(&entry, variant).unwrap_err().to_string();
            assert!(err.contains("TEST-ONLY"), "{err}");
        }
    }

    #[test]
    fn production_refuses_keys_off_the_allowlist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = Paths::under(tmp.path());
        pin_key(&paths, Purpose::EdgeRelease, 1, &signing_key("dev-release"));
        assert!(load_os_pins(&paths, Variant::Production)
            .unwrap_err()
            .to_string()
            .contains("allowlist"));
        assert!(load_os_pins(&paths, Variant::Dev).is_ok());
    }

    #[test]
    fn malformed_pin_directories_fail_closed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = Paths::under(tmp.path());
        let dir = paths.key_pins().join("edge-release");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("01.pub"), "x").unwrap();
        assert!(load_os_pins(&paths, Variant::Dev).is_err());
        std::fs::remove_file(dir.join("01.pub")).unwrap();
        std::fs::write(
            dir.join("1.pub"),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        assert!(load_os_pins(&paths, Variant::Dev).is_err());
    }
}
