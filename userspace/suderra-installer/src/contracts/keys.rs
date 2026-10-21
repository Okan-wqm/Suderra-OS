// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Verifier key store (statements.json `dsse.key_resolution`, DEC-3.3/3.4).
//!
//! The verifier resolves a DSSE keyid to (purpose, epoch, key) from its own
//! store, never from the statement: the keys pinned in the OS image for the
//! os-image purposes, plus, for bundle-only purposes, the anchors of a bundle
//! that itself verified against the fleet-root pin.

use super::encoding::sha256_hex;
use super::registry::Purpose;
use std::collections::BTreeMap;

/// One resolvable key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyEntry {
    /// Purpose the key is pinned or anchored under.
    pub purpose: Purpose,
    /// Its epoch.
    pub epoch: u16,
    /// Raw 32-byte Ed25519 public key.
    pub raw: [u8; 32],
}

/// keyid → key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyStore {
    entries: BTreeMap<String, KeyEntry>,
}

impl KeyStore {
    /// Builds a store; refuses a second key under one keyid or one
    /// (purpose, epoch) slot.
    pub(crate) fn from_entries(
        entries: impl IntoIterator<Item = KeyEntry>,
    ) -> Result<Self, String> {
        let mut store = Self::default();
        for entry in entries {
            store.insert(entry)?;
        }
        Ok(store)
    }

    fn insert(&mut self, entry: KeyEntry) -> Result<(), String> {
        let keyid = sha256_hex(&entry.raw);
        if self
            .entries
            .values()
            .any(|e| e.purpose == entry.purpose && e.epoch == entry.epoch)
        {
            return Err(format!(
                "two keys for {}/{}",
                entry.purpose.as_str(),
                entry.epoch
            ));
        }
        if self.entries.insert(keyid.clone(), entry).is_some() {
            return Err(format!("keyid {keyid} pinned twice"));
        }
        Ok(())
    }

    /// Key for `keyid`.
    pub(crate) fn get(&self, keyid: &str) -> Option<&KeyEntry> {
        self.entries.get(keyid)
    }

    /// Number of keys.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// y of the small-order points of edwards25519 (little-endian, the sign bit
/// masked): the encodings of 0, 1, p - 1, the two points of order 8, and the
/// non-canonical encodings p and p + 1 of 0 and 1 (the list of
/// statements.json `dsse.signature_algorithm`; libsodium's
/// `ge25519_has_small_order`).
const SMALL_ORDER_Y: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// The sign bit of an encoding is the top bit of its last byte; the rest is y.
fn y_bytes(raw: &[u8; 32]) -> [u8; 32] {
    let mut y = *raw;
    if let Some(last) = y.last_mut() {
        *last &= 0x7f;
    }
    y
}

/// RFC 8032 section 5.1.3: an encoding whose y is not below p = 2^255 - 19 is
/// non-canonical. Only y in [p, 2^255) is, and those are the encodings
/// `ed ff .. ff 7f` and above.
fn is_canonical_point(raw: &[u8; 32]) -> bool {
    let [first, middle @ .., last] = y_bytes(raw);
    !(last == 0x7f && middle.iter().all(|b| *b == 0xff) && first >= 0xed)
}

fn is_small_order(raw: &[u8; 32]) -> bool {
    SMALL_ORDER_Y.contains(&y_bytes(raw))
}

/// Whether a key store may admit the 32 bytes as an Ed25519 public key
/// (statements.json `dsse.signature_algorithm`): the canonical encoding of a
/// point that is not small-order. ed25519-dalek `verify_strict` refuses a
/// small-order A but does not check the canonicality of A itself, so the
/// contract closes it here, at admission: a bundle anchor that is not
/// admissible is `anchor-invalid` and an OS pin that is not admissible is no
/// pin (`trust_anchors::admit`). A key that is admissible but not a point of
/// the curve is admitted and never verifies a signature.
pub(crate) fn is_admissible_key(raw: &[u8; 32]) -> bool {
    is_canonical_point(raw) && !is_small_order(raw)
}

/// The keys one verification may resolve against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyView<'a> {
    /// Keys pinned in the OS image.
    pub os: &'a KeyStore,
    /// Bundle-only anchors of a verified bundle, when the call site has one.
    pub bundle: Option<&'a KeyStore>,
}

impl KeyView<'_> {
    /// Resolves `keyid` (OS pins first, then bundle anchors).
    pub(crate) fn get(&self, keyid: &str) -> Option<&KeyEntry> {
        self.os
            .get(keyid)
            .or_else(|| self.bundle.and_then(|b| b.get(keyid)))
    }
}
