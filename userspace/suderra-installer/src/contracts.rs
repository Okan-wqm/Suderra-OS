// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Suderra edge contract v1: the OS root verifier (ADR-048 DEC-3, DEC-25).
//!
//! Implements `contracts/suderra-edge/v1` (vendored at
//! `contracts/suderra-edge/` of this repository): DSSE envelopes signed over
//! the exact payload bytes and verified with ed25519-dalek `verify_strict`,
//! the strict JSON rules, typed statement schemas that deny unknown members,
//! per-purpose and per-epoch key resolution, and every check of
//! statements.json in its normative order. `golden_tests` runs every golden
//! fixture the OS verifier must check and requires its labelled verdict and
//! reason.

pub(crate) mod delivery;
pub(crate) mod dsse;
pub(crate) mod encoding;
pub(crate) mod json;
pub(crate) mod keys;
pub(crate) mod registry;
pub(crate) mod statements;
pub(crate) mod verify;

#[cfg(test)]
mod golden_tests;
