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
    /// /etc/suderra/board (DEC-8.2): only on images with a board_profile.
    pub(crate) fn board_file(&self) -> PathBuf {
        self.at("/etc/suderra/board")
    }
    /// /etc/suderra/features: the features every image declares (DEC-6.8).
    pub(crate) fn features_file(&self) -> PathBuf {
        self.at("/etc/suderra/features")
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
    /// Whether /data is mounted with its layout applied: suderra-data-unlock
    /// creates /data/suderra/os from the data layout (mutable-state.json
    /// `data_partition`), and the installer never creates it itself, so
    /// nothing it writes lands on the rootfs under an unmounted /data.
    pub(crate) fn os_state_available(&self) -> bool {
        std::fs::symlink_metadata(self.os_state()).is_ok_and(|m| m.is_dir())
    }
    /// Fails unless [`Paths::os_state_available`].
    pub(crate) fn require_os_state(&self) -> Result<()> {
        if !self.os_state_available() {
            anyhow::bail!(
                "{} is missing: /data is not mounted or suderra-data-unlock has not applied its layout",
                self.os_state().display()
            );
        }
        Ok(())
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
    /// Installer work state (/var/lib/suderra-installer).
    pub(crate) fn installer_work(&self) -> PathBuf {
        self.at("/data/suderra/os/installer")
    }

    // ---- other /data trees

    /// RAUC and health-gate state (/data/rauc, root:root 0700).
    pub(crate) fn rauc_state(&self) -> PathBuf {
        self.at("/data/rauc")
    }
    /// The agent's health before a pending OS update (DEC-6.8).
    pub(crate) fn pre_update(&self) -> PathBuf {
        self.at("/data/rauc/pre-update.json")
    }

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
    /// suderra-provision-mode's open-window marker (DEC-5.4).
    pub(crate) fn provisioning_open(&self) -> PathBuf {
        self.at("/run/suderra-os/provisioning-open")
    }
    /// suderra-provision-mode's closed-window marker.
    pub(crate) fn provisioning_closed(&self) -> PathBuf {
        self.at("/run/suderra-os/provisioning-closed")
    }
    /// The open window's deadline in seconds of uptime.
    pub(crate) fn provisioning_expires(&self) -> PathBuf {
        self.at("/run/suderra-os/provisioning-expires")
    }
    /// Kernel routing table, for the provisioning interface (DEC-5.4).
    pub(crate) fn proc_route(&self) -> PathBuf {
        self.at("/proc/net/route")
    }
    /// Seconds since boot, against the provisioning window's deadline.
    pub(crate) fn proc_uptime(&self) -> PathBuf {
        self.at("/proc/uptime")
    }
    /// Device-mapper names, for the health check.
    pub(crate) fn dev_mapper(&self) -> PathBuf {
        self.at("/dev/mapper")
    }
    /// The TPM 2.0 resource manager node (the health gate's TPM probe).
    pub(crate) fn tpm_resource_manager(&self) -> PathBuf {
        self.at("/dev/tpmrm0")
    }
    /// The kernel's view of the TPM.
    pub(crate) fn sys_tpm(&self) -> PathBuf {
        self.at("/sys/class/tpm/tpm0")
    }
    /// The system RTC node: hctosys reads it, chrony's rtcsync writes it.
    pub(crate) fn rtc_device(&self) -> PathBuf {
        self.at("/dev/rtc0")
    }
    /// The kernel's view of the system RTC.
    pub(crate) fn sys_rtc(&self) -> PathBuf {
        self.at("/sys/class/rtc/rtc0")
    }
    /// The link udev makes to the board's own hardware watchdog, the device
    /// systemd PID1 opens (`WatchdogDevice=` of the board's system.conf.d
    /// drop-in, ADR-048 DEC-6.6).
    pub(crate) fn watchdog_link(&self) -> PathBuf {
        self.at("/dev/suderra-watchdog")
    }
    /// The kernel's watchdog class: one directory per `/dev/watchdogN`.
    pub(crate) fn sys_watchdog_class(&self) -> PathBuf {
        self.at("/sys/class/watchdog")
    }
    /// The RevPi PiBridge process image device piControl creates.
    pub(crate) fn picontrol_device(&self) -> PathBuf {
        self.at("/dev/piControl0")
    }
    /// The EFI `SecureBoot` variable as efivarfs exposes it (four attribute
    /// bytes, then the one-byte value).
    pub(crate) fn secure_boot_variable(&self) -> PathBuf {
        self.at("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    }
    /// The kernel's mount table.
    pub(crate) fn proc_mountinfo(&self) -> PathBuf {
        self.at("/proc/self/mountinfo")
    }
}
