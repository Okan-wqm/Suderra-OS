// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer policy apply`: fail-safe firewall mode selection
//! (ADR-048 DEC-5.4, DEC-11.2, DEC-11.3, DEC-11.9).
//!
//! The appliance ruleset is the default. The provisioning ruleset loads only
//! while the root-owned lifecycle is PROVISIONING or MAINTENANCE *and* the
//! provisioning window is open (suderra-provision-mode's root-owned markers
//! in /run/suderra-os: open, not closed, not past its uptime deadline), and
//! only scoped to the interface that carries the default route: root renders
//! `define provision_iface = "<iface>"` (a validated interface name, never
//! string-built from untrusted text) in front of the image's provisioning
//! ruleset, which must use `$provision_iface`. Every program is checked with
//! `nft -c` before `nft -f`; the hash of the loaded ruleset is recorded for
//! the health check under /run/suderra-os, because it describes the ruleset
//! loaded in this boot and must be recordable when /data is unavailable (the
//! device that most needs to report a data-unlock alarm keeps its network).

use crate::cli::{PolicyArgs, PolicyCommand};
use crate::cmd::lifecycle;
use crate::contracts::encoding::{now_timestamp, sha256_hex};
use crate::contracts::registry::LifecycleState;
use crate::fsutil::{ensure_dir, read_root_file, write_atomic};
use crate::paths::Paths;
use crate::system::{Runner, SystemRunner};
use anyhow::{bail, Context, Result};
use std::path::Path;

/// The ruleset a lifecycle state selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ruleset {
    /// Appliance (no inbound SSH).
    Appliance,
    /// Provisioning SSH on one interface.
    Provisioning {
        /// Interface carrying the default route.
        iface: String,
    },
}

/// Linux interface name: 1..15 bytes of `[A-Za-z0-9_.-]`.
pub(crate) fn iface_name_ok(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// The interface of the lowest-metric IPv4 default route in
/// /proc/net/route text.
pub(crate) fn default_route_iface(route: &str) -> Option<String> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    route
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (iface, destination, flags, metric, mask) = (
                cols.first()?,
                cols.get(1)?,
                cols.get(3)?,
                cols.get(6)?,
                cols.get(7)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let metric: u32 = metric.parse().ok()?;
            (*destination == "00000000"
                && *mask == "00000000"
                && flags & RTF_UP != 0
                && flags & RTF_GATEWAY != 0
                && iface_name_ok(iface))
            .then(|| (metric, (*iface).to_owned()))
        })
        .min()
        .map(|(_, iface)| iface)
}

/// Whether the provisioning window is open: suderra-provision-mode wrote its
/// open marker and deadline, the window has not been closed, and the uptime
/// deadline has not passed. Anything unreadable is a closed window.
pub(crate) fn window_open(paths: &Paths) -> bool {
    let read = |path: std::path::PathBuf| std::fs::read_to_string(path).ok();
    let seconds = |text: Option<String>| -> Option<u64> {
        text?
            .split_whitespace()
            .next()?
            .split('.')
            .next()?
            .parse()
            .ok()
    };
    if !paths.provisioning_open().is_file() || paths.provisioning_closed().exists() {
        return false;
    }
    match (
        seconds(read(paths.provisioning_expires())),
        seconds(read(paths.proc_uptime())),
    ) {
        (Some(expires), Some(uptime)) => uptime < expires,
        _ => false,
    }
}

/// Selects the ruleset for the current lifecycle and provisioning window
/// (DEC-5.4, DEC-11.3).
pub(crate) fn select(paths: &Paths, now: &str) -> Result<Ruleset> {
    let state = lifecycle::effective(paths, now);
    if !matches!(
        state,
        LifecycleState::Provisioning | LifecycleState::Maintenance
    ) || !window_open(paths)
    {
        return Ok(Ruleset::Appliance);
    }
    let route = std::fs::read_to_string(paths.proc_route()).unwrap_or_default();
    Ok(match default_route_iface(&route) {
        Some(iface) => Ruleset::Provisioning { iface },
        None => Ruleset::Appliance,
    })
}

fn nft_string(path: &Path) -> Result<String> {
    let text = path.to_str().context("ruleset path is not UTF-8")?;
    if text.contains('"') || text.contains('\n') {
        bail!("ruleset path cannot be quoted for nft");
    }
    Ok(format!("\"{text}\""))
}

/// The nft program for `ruleset`.
pub(crate) fn render(paths: &Paths, ruleset: &Ruleset) -> Result<String> {
    match ruleset {
        Ruleset::Appliance => Ok(format!("include {}\n", nft_string(&paths.nft_appliance())?)),
        Ruleset::Provisioning { iface } => {
            if !iface_name_ok(iface) {
                bail!("interface {iface:?} is not a valid name");
            }
            let source = std::fs::read_to_string(paths.nft_provisioning())
                .with_context(|| format!("cannot read {}", paths.nft_provisioning().display()))?;
            if !source.contains("$provision_iface") {
                bail!("the provisioning ruleset does not scope SSH to $provision_iface (DEC-5.4)");
            }
            Ok(format!(
                "define provision_iface = \"{iface}\"\ninclude {}\n",
                nft_string(&paths.nft_provisioning())?
            ))
        }
    }
}

/// SHA-256 of `nft list ruleset`.
pub(crate) fn loaded_ruleset_hash(runner: &dyn Runner) -> Result<String> {
    Ok(sha256_hex(&runner.output("nft", &["list", "ruleset"])?))
}

fn record_dir(paths: &Paths) -> std::path::PathBuf {
    paths.run_os().join("firewall")
}

fn record_path(paths: &Paths) -> std::path::PathBuf {
    record_dir(paths).join("loaded.sha256")
}

/// Hash recorded by the last successful apply.
pub(crate) fn recorded_hash(paths: &Paths) -> Result<Option<String>> {
    Ok(read_root_file(&record_path(paths), 128)?
        .and_then(|b| String::from_utf8(b).ok())
        .map(|t| t.trim().to_owned()))
}

fn load(paths: &Paths, runner: &dyn Runner, program: &str) -> Result<()> {
    let dir = paths.run_os().join("nft");
    ensure_dir(&paths.run_os(), 0o700)?;
    ensure_dir(&dir, 0o700)?;
    let file = dir.join("ruleset.nft");
    write_atomic(&file, program.as_bytes(), 0o600, None)?;
    let file = file.to_str().context("ruleset path is not UTF-8")?;
    runner
        .output("nft", &["-c", "-f", file])
        .context("nft -c rejected the ruleset")?;
    runner
        .output("nft", &["-f", file])
        .context("nft -f failed")?;
    Ok(())
}

/// Applies the selected ruleset (falling back to the appliance ruleset) and
/// records the loaded hash; returns what was loaded.
pub(crate) fn apply(paths: &Paths, runner: &dyn Runner, now: &str) -> Result<Ruleset> {
    let selected = select(paths, now)?;
    let loaded = match render(paths, &selected).and_then(|p| load(paths, runner, &p)) {
        Ok(()) => selected,
        Err(e) if selected != Ruleset::Appliance => {
            tracing::error!("provisioning ruleset not loaded, falling back to appliance: {e:#}");
            load(paths, runner, &render(paths, &Ruleset::Appliance)?)?;
            Ruleset::Appliance
        }
        Err(e) => return Err(e),
    };
    let hash = loaded_ruleset_hash(runner)?;
    ensure_dir(&paths.run_os(), 0o700)?;
    ensure_dir(&record_dir(paths), 0o700)?;
    write_atomic(
        &record_path(paths),
        format!("{hash}\n").as_bytes(),
        0o600,
        None,
    )?;
    Ok(loaded)
}

/// Whether the loaded ruleset is the one `apply` checked and recorded this
/// boot (the health predicate and suderra-lockdown-status).
pub(crate) fn loaded_matches_record(paths: &Paths, runner: &dyn Runner) -> Result<bool> {
    let recorded = recorded_hash(paths)?;
    Ok(match loaded_ruleset_hash(runner) {
        Ok(hash) => recorded.as_deref() == Some(hash.as_str()),
        Err(_) => false,
    })
}

/// `suderra-installer policy apply|verify`.
pub(crate) fn run(args: PolicyArgs) -> Result<()> {
    let paths = Paths::system()?;
    match args.command {
        PolicyCommand::Apply => match apply(&paths, &SystemRunner, &now_timestamp())? {
            Ruleset::Appliance => println!("appliance"),
            Ruleset::Provisioning { iface } => println!("provisioning {iface}"),
        },
        PolicyCommand::Verify => {
            if !loaded_matches_record(&paths, &SystemRunner)? {
                bail!("the loaded ruleset is not the one policy apply recorded this boot");
            }
            println!("loaded ruleset matches the recorded hash");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRunner;

    const NOW: &str = "2026-10-20T12:00:00Z";

    const ROUTE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth1\t00000000\t0102A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n\
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    #[test]
    fn default_route_interface_is_the_lowest_metric() {
        assert_eq!(default_route_iface(ROUTE).as_deref(), Some("eth0"));
        assert_eq!(default_route_iface("Iface\tDestination\n"), None);
        assert!(!iface_name_ok("eth0\"; flush ruleset"));
        assert!(!iface_name_ok("averyveryverylongname"));
    }

    fn setup(state: Option<LifecycleState>) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = Paths::under(tmp.path());
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::write(paths.nft_appliance(), "flush ruleset\n").unwrap();
        std::fs::write(
            paths.nft_provisioning(),
            "flush ruleset\ntable inet f { chain input { iifname $provision_iface tcp dport 22 accept } }\n",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("proc/net")).unwrap();
        std::fs::write(paths.proc_route(), ROUTE).unwrap();
        std::fs::create_dir_all(paths.os_state()).unwrap();
        if let Some(state) = state {
            lifecycle::write(&paths, state, None).unwrap();
        }
        open_window(&paths, 600, 7800);
        (tmp, paths)
    }

    /// The markers suderra-provision-mode writes when it opens a window at
    /// `uptime` that closes at `expires` (seconds since boot).
    fn open_window(paths: &Paths, uptime: u64, expires: u64) {
        std::fs::create_dir_all(paths.run_os()).unwrap();
        std::fs::write(paths.provisioning_open(), "").unwrap();
        std::fs::write(paths.provisioning_expires(), format!("{expires}\n")).unwrap();
        std::fs::write(paths.proc_uptime(), format!("{uptime}.42 1234.00\n")).unwrap();
    }

    #[test]
    fn provisioning_rules_load_only_while_the_window_is_open() {
        let provisioning = Ruleset::Provisioning {
            iface: "eth0".into(),
        };
        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            provisioning
        );

        // Expired: past the uptime deadline while still PROVISIONING.
        open_window(&paths, 7800, 7800);
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Appliance
        );

        // Closed by reconcile or lockdown (the closed marker wins).
        open_window(&paths, 600, 7800);
        std::fs::write(paths.provisioning_closed(), "").unwrap();
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Appliance
        );

        // Never opened, or the deadline is unreadable.
        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        std::fs::remove_file(paths.provisioning_open()).unwrap();
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Appliance
        );
        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        std::fs::write(paths.provisioning_expires(), "soon\n").unwrap();
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Appliance
        );
    }

    #[test]
    fn verify_matches_only_the_ruleset_apply_recorded() {
        let (_tmp, paths) = setup(None);
        let runner = FakeRunner::default();
        assert!(
            !loaded_matches_record(&paths, &runner).unwrap(),
            "nothing recorded"
        );
        apply(&paths, &runner, NOW).unwrap();
        assert!(loaded_matches_record(&paths, &runner).unwrap());
        let changed = FakeRunner {
            ruleset: b"table inet other {}\n".to_vec(),
            ..FakeRunner::default()
        };
        assert!(!loaded_matches_record(&paths, &changed).unwrap());
    }

    #[test]
    fn apply_loads_and_records_without_data() {
        let (_tmp, paths) = setup(None);
        std::fs::remove_dir_all(paths.os_state()).unwrap();
        let runner = FakeRunner::default();
        assert_eq!(apply(&paths, &runner, NOW).unwrap(), Ruleset::Appliance);
        assert_eq!(recorded_hash(&paths).unwrap(), Some(runner.ruleset_hash()));
        assert!(
            !paths.os_state().exists(),
            "nothing is written under an unmounted /data"
        );
    }

    #[test]
    fn provisioning_rules_load_only_in_provisioning_and_are_interface_scoped() {
        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        let runner = FakeRunner::default();
        assert_eq!(
            apply(&paths, &runner, NOW).unwrap(),
            Ruleset::Provisioning {
                iface: "eth0".into()
            }
        );
        let program = std::fs::read_to_string(paths.run_os().join("nft/ruleset.nft")).unwrap();
        assert!(program.starts_with("define provision_iface = \"eth0\"\n"));
        assert_eq!(recorded_hash(&paths).unwrap(), Some(runner.ruleset_hash()));

        for state in [
            None,
            Some(LifecycleState::Active),
            Some(LifecycleState::Factory),
        ] {
            let (_tmp, paths) = setup(state);
            assert_eq!(
                apply(&paths, &FakeRunner::default(), NOW).unwrap(),
                Ruleset::Appliance,
                "{state:?}"
            );
        }
    }

    #[test]
    fn an_ended_maintenance_window_loads_the_appliance_ruleset() {
        let (_tmp, paths) = setup(None);
        lifecycle::write(
            &paths,
            LifecycleState::Maintenance,
            Some("2026-10-20T13:00:00Z".into()),
        )
        .unwrap();
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Provisioning {
                iface: "eth0".into()
            }
        );
        assert_eq!(
            apply(&paths, &FakeRunner::default(), "2026-10-20T13:00:00Z").unwrap(),
            Ruleset::Appliance,
            "the window has ended even though init has not recorded it"
        );
    }

    #[test]
    fn an_unscoped_or_failing_provisioning_ruleset_falls_back_to_appliance() {
        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        std::fs::write(
            paths.nft_provisioning(),
            "table inet f { chain input { tcp dport 22 accept } }\n",
        )
        .unwrap();
        assert_eq!(
            apply(&paths, &FakeRunner::default(), NOW).unwrap(),
            Ruleset::Appliance
        );

        let (_tmp, paths) = setup(Some(LifecycleState::Provisioning));
        let runner = FakeRunner {
            fail_check_containing: Some("provision_iface".into()),
            ..FakeRunner::default()
        };
        assert_eq!(apply(&paths, &runner, NOW).unwrap(), Ruleset::Appliance);
    }
}
