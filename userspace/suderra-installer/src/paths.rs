// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Every path the root installer reads or writes (ADR-048 DEC-4.2, DEC-24;
//! contracts mutable-state.json).
//!
//! Paths are compile-time facts of the image: nothing here is taken from the
//! environment or the command line (DEC-19). Tests build the same layout
//! under a temporary root.

use anyhow::{Context, Result};
use nix::unistd::{Gid, Group};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

/// The installer's filesystem layout.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    root: PathBuf,
    /// Group of the agent user, for files under /run/suderra and
    /// /data/suderra/site (root:suderra, DEC-4.2). `None` only in tests.
    agent_group: Option<Gid>,
}

impl Paths {
    /// The image layout rooted at `/`.
    pub(crate) fn system() -> Result<Self> {
        let group = Group::from_name("suderra")
            .context("cannot look up the suderra group")?
            .context("the image has no suderra group")?;
        Ok(Self {
            root: PathBuf::from("/"),
            agent_group: Some(group.gid),
        })
    }

    /// The same layout under `root`, without group ownership changes.
    #[cfg(test)]
    pub(crate) fn under(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            agent_group: None,
        }
    }

    fn at(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Group the agent reads root-written files with.
    pub(crate) fn agent_group(&self) -> Option<Gid> {
        self.agent_group
    }

    // ---- verity rootfs (image facts)

    /// /etc/os-release.
    pub(crate) fn os_release(&self) -> PathBuf {
        self.at("/etc/os-release")
    }
    /// /etc/suderra/board (DEC-8.2).
    pub(crate) fn board_file(&self) -> PathBuf {
        self.at("/etc/suderra/board")
    }
    /// /etc/suderra/kernel-config (statements.json compatibility).
    pub(crate) fn kernel_config(&self) -> PathBuf {
        self.at("/etc/suderra/kernel-config")
    }
    /// /etc/suderra/keys/<purpose>/<epoch>.pub (DEC-3.4).
    pub(crate) fn key_pins(&self) -> PathBuf {
        self.at("/etc/suderra/keys")
    }
    /// Provisioning API base URL of the image.
    pub(crate) fn cloud_endpoint(&self) -> PathBuf {
        self.at("/etc/suderra/cloud-endpoint")
    }
    /// Extra CA for the provisioning API (dev and QEMU images).
    pub(crate) fn cloud_ca(&self) -> PathBuf {
        self.at("/etc/suderra/cloud-ca.pem")
    }
    /// The image's appliance ruleset (DEC-11).
    pub(crate) fn nft_appliance(&self) -> PathBuf {
        self.at("/etc/nftables.conf")
    }
    /// The image's provisioning ruleset (DEC-11.3).
    pub(crate) fn nft_provisioning(&self) -> PathBuf {
        self.at("/etc/nftables.provisioning.conf")
    }

    // ---- /data/suderra/os (root:root 0700)

    /// Root-owned OS state.
    pub(crate) fn os_state(&self) -> PathBuf {
        self.at("/data/suderra/os")
    }
    /// Hardware identity and recorded tenant/device.
    pub(crate) fn identity_dir(&self) -> PathBuf {
        self.at("/data/suderra/os/identity")
    }
    /// Accepted sequence and digest per statement kind.
    pub(crate) fn seq_dir(&self) -> PathBuf {
        self.at("/data/suderra/os/seq")
    }
    /// Min-epoch ratchet per purpose.
    pub(crate) fn ratchet_dir(&self) -> PathBuf {
        self.at("/data/suderra/os/ratchet")
    }
    /// Install receipt, release statement and rollback floor.
    pub(crate) fn edge_state(&self) -> PathBuf {
        self.at("/data/suderra/os/edge")
    }
    /// Lifecycle store.
    pub(crate) fn lifecycle_store(&self) -> PathBuf {
        self.at("/data/suderra/os/lifecycle")
    }
    /// Typed results.
    pub(crate) fn results_store(&self) -> PathBuf {
        self.at("/data/suderra/os/results")
    }
    /// Firewall last-known-good record.
    pub(crate) fn firewall_state(&self) -> PathBuf {
        self.at("/data/suderra/os/firewall")
    }
    /// Installer work state (/var/lib/suderra-installer).
    pub(crate) fn installer_work(&self) -> PathBuf {
        self.at("/data/suderra/os/installer")
    }

    // ---- other /data trees

    /// Release tree bound read-only at /opt/suderra/edge.
    pub(crate) fn edge_root(&self) -> PathBuf {
        self.at("/data/suderra/edge")
    }
    /// Site tree bound read-only at /var/lib/suderra-site.
    pub(crate) fn site_root(&self) -> PathBuf {
        self.at("/data/suderra/site")
    }
    /// The agent's state directory (agent-owned; read with openat only).
    pub(crate) fn agent_state(&self) -> PathBuf {
        self.at("/data/suderra/agent/state")
    }

    // ---- tmpfs

    /// /run/suderra (root:suderra 0750): the agent's view of root state.
    pub(crate) fn run_suderra(&self) -> PathBuf {
        self.at("/run/suderra")
    }
    /// /run/suderra/results.
    pub(crate) fn run_results(&self) -> PathBuf {
        self.at("/run/suderra/results")
    }
    /// /run/suderra-os (root:root 0700).
    pub(crate) fn run_os(&self) -> PathBuf {
        self.at("/run/suderra-os")
    }
    /// The provisioning request root issued for the next delivery
    /// (`edge request`); its nonce is shown on the console (delivery.json
    /// `usb.nonce`) and the delivery must echo it.
    pub(crate) fn provisioning_request(&self) -> PathBuf {
        self.at("/run/suderra-os/provisioning-request.json")
    }
    /// Lock shared by agent and OS update operations (DEC-2.3).
    pub(crate) fn update_lock(&self) -> PathBuf {
        self.at("/run/suderra-update.lock")
    }
    /// The agent's health report (DEC-6.3).
    pub(crate) fn agent_health(&self) -> PathBuf {
        self.at("/run/suderra/agent-health/health.json")
    }
    /// Kernel routing table, for the provisioning interface (DEC-5.4).
    pub(crate) fn proc_route(&self) -> PathBuf {
        self.at("/proc/net/route")
    }
    /// Device-mapper names, for the health check.
    pub(crate) fn dev_mapper(&self) -> PathBuf {
        self.at("/dev/mapper")
    }
}
