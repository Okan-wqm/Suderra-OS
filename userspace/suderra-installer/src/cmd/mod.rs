// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Command implementations.

pub mod edge;
pub mod health;
pub mod lifecycle;
pub mod policy;
pub mod result;
pub mod site;

#[cfg(any(test, feature = "package-commands"))]
pub mod install;
#[cfg(any(test, feature = "package-commands"))]
pub mod list;
#[cfg(any(test, feature = "package-commands"))]
pub mod remove;
#[cfg(any(test, feature = "package-commands"))]
pub mod rollback;
#[cfg(any(test, feature = "package-commands"))]
pub mod status;
#[cfg(any(test, feature = "package-commands"))]
pub mod upgrade;
