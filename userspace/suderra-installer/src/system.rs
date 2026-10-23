// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! External programs the root installer drives (systemctl, nft and the
//! image's own time helper), behind a trait so policy and health logic are
//! testable without a running system.

use anyhow::{bail, Context, Result};
use std::process::Command;

/// Runs a program from the verity rootfs and returns its stdout.
pub(crate) trait Runner {
    /// Runs `program args...`; non-zero exit is an error.
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>>;
}

/// Absolute paths of the programs on the image; nothing is resolved from
/// PATH (DEC-19).
fn absolute(program: &str) -> Result<&'static str> {
    Ok(match program {
        "systemctl" => "/usr/bin/systemctl",
        "nft" => "/usr/sbin/nft",
        "suderra-time-state" => "/usr/sbin/suderra-time-state",
        other => bail!("program {other} is not allowed"),
    })
}

/// The real system.
pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        let path = absolute(program)?;
        let out = Command::new(path)
            .args(args)
            .env_clear()
            .output()
            .with_context(|| format!("cannot run {path}"))?;
        if !out.status.success() {
            bail!(
                "{path} {} exited with {}: {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out.stdout)
    }
}
