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
