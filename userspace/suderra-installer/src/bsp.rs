// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Probes of the board support an image declares (ADR-048 DEC-6.8).
//!
//! The health predicate probes only what the image declares in
//! `/etc/suderra/features` (a build-time fact of the signed image) and never
//! what it happens to find: a declared feature that is absent is a failure, an
//! undeclared one is not looked for. Each probe reads the kernel's own view of
//! the device (sysfs, efivarfs) and answers yes or no; a device that is there
//! but not working answers no.
//!
//! - **TPM**: `/dev/tpmrm0` exists and the kernel says the TPM implements TCG
//!   major version 2 (`/sys/class/tpm/tpm0/tpm_version_major`,
//!   Documentation/ABI/stable/sysfs-class-tpm).
//! - **RTC**: `/dev/rtc0` exists and a driver is bound to it
//!   (`/sys/class/rtc/rtc0/name`, Documentation/ABI/testing/sysfs-class-rtc).
//! - **Hardware watchdog**: systemd PID1 holds the board's timer open
//!   (docs/operations/watchdog.md). `/dev/suderra-watchdog` is the link udev
//!   makes to it by identity; its class directory says `state` is `active`
//!   once PID1 has started it, and on a production image `nowayout` is `1`, so
//!   that nothing can stop it again (Documentation/ABI/testing/
//!   sysfs-class-watchdog). Both attributes exist only in a kernel with
//!   `CONFIG_WATCHDOG_SYSFS`, which the kernel-config contract requires of
//!   every board; without it the probe fails, which is the right answer for
//!   a board whose watchdog cannot be seen.
//! - **piControl**: `/dev/piControl0` exists (RevPi Connect 4; the module is
//!   loaded by systemd-modules-load and creates the node).
//! - **Secure Boot**: the EFI `SecureBoot` variable reads 1 (efivarfs gives
//!   four attribute bytes, then the value), which needs `CONFIG_EFIVAR_FS`.

use crate::fsutil::read_root_file;
use crate::paths::Paths;
use crate::variant::{OsFacts, Variant};
use std::path::Path;

/// The declared features that are probed as board support and fail with
/// `bsp-probe-failed` (contracts statements.json: "RTC, PID1 watchdog,
/// /dev/piControl0 or Secure Boot"). `tpm` has its own reason.
pub(crate) const PROBED_FEATURES: [&str; 4] = ["rtc", "watchdog", "picontrol", "secure-boot"];

/// A sysfs attribute is a page; its `stat` size says 4096 whatever it holds.
const SYSFS_MAX: u64 = 8192;

fn present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The trimmed text of a sysfs attribute; `None` when it cannot be read.
fn attribute(path: &Path) -> Option<String> {
    let bytes = read_root_file(path, SYSFS_MAX).ok().flatten()?;
    Some(String::from_utf8_lossy(&bytes).trim().to_owned())
}

/// A TPM 2.0 behind the kernel's resource manager.
pub(crate) fn tpm_reachable(paths: &Paths) -> bool {
    present(&paths.tpm_resource_manager())
        && attribute(&paths.sys_tpm().join("tpm_version_major")).as_deref() == Some("2")
}

fn rtc_present(paths: &Paths) -> bool {
    present(&paths.rtc_device())
        && attribute(&paths.sys_rtc().join("name")).is_some_and(|name| !name.is_empty())
}

/// `watchdogN` and nothing else: the one component taken from a link target
/// is joined to the sysfs class directory.
fn is_watchdog_name(name: &str) -> bool {
    name.strip_prefix("watchdog")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn watchdog_armed(paths: &Paths, variant: Variant) -> bool {
    let Ok(target) = std::fs::read_link(paths.watchdog_link()) else {
        return false;
    };
    let Some(name) = target
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| is_watchdog_name(n))
    else {
        return false;
    };
    let class = paths.sys_watchdog_class().join(name);
    attribute(&class.join("state")).as_deref() == Some("active")
        && (variant != Variant::Production
            || attribute(&class.join("nowayout")).as_deref() == Some("1"))
}

fn picontrol_present(paths: &Paths) -> bool {
    present(&paths.picontrol_device())
}

fn secure_boot_enabled(paths: &Paths) -> bool {
    matches!(
        read_root_file(&paths.secure_boot_variable(), 16),
        Ok(Some(bytes)) if bytes.len() == 5 && bytes[4] == 1
    )
}

/// Whether the probe of a declared feature passes. A name that is not in
/// [`PROBED_FEATURES`] is not a probe.
fn probe(feature: &str, paths: &Paths, os: &OsFacts) -> bool {
    match feature {
        "rtc" => rtc_present(paths),
        "watchdog" => watchdog_armed(paths, os.variant),
        "picontrol" => picontrol_present(paths),
        "secure-boot" => secure_boot_enabled(paths),
        _ => true,
    }
}

/// The declared features whose probe fails, in [`PROBED_FEATURES`] order.
pub(crate) fn failed_probes(paths: &Paths, os: &OsFacts) -> Vec<&'static str> {
    PROBED_FEATURES
        .into_iter()
        .filter(|feature| os.features.contains(*feature) && !probe(feature, paths, os))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::image;
    use std::os::unix::fs::symlink;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A production image's facts with `features` declared, over a fake root.
    fn declared(root: &Path, features: &str) -> (Paths, OsFacts) {
        let (paths, _) = image(root);
        write(
            &paths.os_release(),
            "NAME=\"Suderra OS\"\nID=suderra-os\nVERSION_ID=1.0.0\nVARIANT=prod\nSUDERRA_AGENT_ABI=1-1\n",
        );
        write(
            &paths.features_file(),
            &format!("FEATURES=\"{features}\"\n"),
        );
        let os = OsFacts::load(&paths).unwrap();
        assert_eq!(os.variant, Variant::Production);
        (paths, os)
    }

    /// The fake image carries the TPM it declares; take it away.
    fn remove_tpm(paths: &Paths) {
        std::fs::remove_file(paths.tpm_resource_manager()).unwrap();
        std::fs::remove_file(paths.sys_tpm().join("tpm_version_major")).unwrap();
    }

    fn watchdog(paths: &Paths, link_target: &str, state: &str, nowayout: &str) {
        let class = paths.sys_watchdog_class().join("watchdog0");
        write(&class.join("state"), &format!("{state}\n"));
        write(&class.join("nowayout"), &format!("{nowayout}\n"));
        std::fs::create_dir_all(paths.watchdog_link().parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(paths.watchdog_link());
        symlink(link_target, paths.watchdog_link()).unwrap();
    }

    #[test]
    fn nothing_is_probed_that_the_image_does_not_declare() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "verity luks");
        remove_tpm(&paths);
        assert!(failed_probes(&paths, &os).is_empty());
        assert!(!tpm_reachable(&paths), "an undeclared TPM is simply absent");
    }

    #[test]
    fn a_declared_probe_that_finds_nothing_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "rtc watchdog picontrol secure-boot");
        assert_eq!(
            failed_probes(&paths, &os),
            ["rtc", "watchdog", "picontrol", "secure-boot"]
        );
    }

    #[test]
    fn the_tpm_must_be_a_2_0_behind_the_resource_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = declared(tmp.path(), "tpm");
        remove_tpm(&paths);
        assert!(!tpm_reachable(&paths));
        write(&paths.tpm_resource_manager(), "");
        assert!(!tpm_reachable(&paths), "a node without the kernel's TPM");
        write(&paths.sys_tpm().join("tpm_version_major"), "1\n");
        assert!(!tpm_reachable(&paths), "a TPM 1.2");
        write(&paths.sys_tpm().join("tpm_version_major"), "2\n");
        assert!(tpm_reachable(&paths));
        std::fs::remove_file(paths.tpm_resource_manager()).unwrap();
        assert!(!tpm_reachable(&paths), "the TPM is there, its node is not");
    }

    #[test]
    fn the_rtc_needs_its_node_and_a_bound_driver() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "rtc");
        write(&paths.rtc_device(), "");
        assert_eq!(failed_probes(&paths, &os), ["rtc"], "no driver is bound");
        write(&paths.sys_rtc().join("name"), "\n");
        assert_eq!(
            failed_probes(&paths, &os),
            ["rtc"],
            "a nameless class device"
        );
        write(&paths.sys_rtc().join("name"), "rtc-pcf2127 1-0051\n");
        assert!(failed_probes(&paths, &os).is_empty());
    }

    #[test]
    fn the_watchdog_is_armed_when_pid1_holds_the_boards_timer() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "watchdog");
        watchdog(&paths, "watchdog0", "inactive", "1");
        assert_eq!(
            failed_probes(&paths, &os),
            ["watchdog"],
            "PID1 has not opened it"
        );
        watchdog(&paths, "watchdog0", "active", "0");
        assert_eq!(
            failed_probes(&paths, &os),
            ["watchdog"],
            "a production kernel that lets userspace stop it"
        );
        watchdog(&paths, "watchdog0", "active", "1");
        assert!(failed_probes(&paths, &os).is_empty());
        // udev's link is relative; an absolute one names the same class directory.
        watchdog(&paths, "/dev/watchdog0", "active", "1");
        assert!(failed_probes(&paths, &os).is_empty());
    }

    #[test]
    fn a_development_image_is_not_held_to_nowayout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        write(&paths.features_file(), "FEATURES=\"watchdog\"\n");
        let os = OsFacts::load(&paths).unwrap();
        assert_eq!(os.variant, Variant::Dev);
        watchdog(&paths, "watchdog0", "active", "0");
        assert!(failed_probes(&paths, &os).is_empty());
        watchdog(&paths, "watchdog0", "inactive", "0");
        assert_eq!(failed_probes(&paths, &os), ["watchdog"]);
    }

    #[test]
    fn the_watchdog_link_names_a_class_directory_and_nothing_else() {
        assert!(is_watchdog_name("watchdog0"));
        assert!(is_watchdog_name("watchdog12"));
        for name in [
            "watchdog",
            "watchdogx",
            "watchdog0x",
            "..",
            "",
            "watchdog-1",
            "Watchdog0",
        ] {
            assert!(!is_watchdog_name(name), "{name:?}");
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "watchdog");
        watchdog(&paths, "watchdog0", "active", "1");
        // A link that points somewhere else is not the board's timer, even
        // when a directory of that name exists.
        write(
            &paths.sys_watchdog_class().join("elsewhere/state"),
            "active\n",
        );
        write(
            &paths.sys_watchdog_class().join("elsewhere/nowayout"),
            "1\n",
        );
        let _ = std::fs::remove_file(paths.watchdog_link());
        symlink("../../sys/class/watchdog/elsewhere", paths.watchdog_link()).unwrap();
        assert_eq!(failed_probes(&paths, &os), ["watchdog"]);
        // A link to nothing.
        let _ = std::fs::remove_file(paths.watchdog_link());
        symlink("watchdog7", paths.watchdog_link()).unwrap();
        assert_eq!(failed_probes(&paths, &os), ["watchdog"]);
        // A regular file in the link's place is not what udev makes.
        let _ = std::fs::remove_file(paths.watchdog_link());
        write(&paths.watchdog_link(), "");
        assert_eq!(failed_probes(&paths, &os), ["watchdog"]);
    }

    #[test]
    fn picontrol_is_its_node() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "picontrol");
        assert_eq!(failed_probes(&paths, &os), ["picontrol"]);
        write(&paths.picontrol_device(), "");
        assert!(failed_probes(&paths, &os).is_empty());
    }

    #[test]
    fn secure_boot_is_the_variable_reading_one() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, os) = declared(tmp.path(), "secure-boot");
        let variable = paths.secure_boot_variable();
        let attributes = [0x06, 0x00, 0x00, 0x00];
        for (bytes, ok) in [
            (&[attributes.as_slice(), &[1]].concat(), true),
            (&[attributes.as_slice(), &[0]].concat(), false),
            (&[attributes.as_slice(), &[2]].concat(), false),
            (&attributes.to_vec(), false),
            (&[attributes.as_slice(), &[1, 1]].concat(), false),
        ] {
            std::fs::create_dir_all(variable.parent().unwrap()).unwrap();
            std::fs::write(&variable, bytes).unwrap();
            assert_eq!(failed_probes(&paths, &os).is_empty(), ok, "{bytes:?}");
        }
    }
}
