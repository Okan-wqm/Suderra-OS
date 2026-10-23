// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer health check` and `health preflight`: the OS and agent
//! predicate of the health gate (ADR-048 DEC-6.8, DEC-23).
//!
//! It does not depend on RAUC and runs on every image; the RAUC health gate
//! calls it before mark-good. The OS checks run on every image, with or
//! without a board: the features they check come from the image's build-time
//! declaration (`/etc/suderra/features`), not from probing, so an absent
//! declared feature is a failure, and the loaded firewall must be the one
//! `policy apply` checked and recorded this boot.
//!
//! The OS checks are the declared verity and `/data` mapper, the loaded
//! firewall, the clock not below the time floor, a TPM that answers where the
//! image declares one, and the board support it declares (RTC, the PID1
//! hardware watchdog, `/dev/piControl0`, Secure Boot; `crate::bsp`).
//!
//! The lifecycle and agent checks apply only on an image with a board (only
//! such an image has a lifecycle and an agent). A device whose lifecycle is
//! ACTIVE must also have closed its technician path: provisioning mode, its
//! SSH server and the one-time-password shadow end with lockdown, and an
//! ACTIVE device that still has one disagrees with its own store. The agent counts only when
//! the lifecycle is ACTIVE (a root-verified activation receipt) *and* the
//! pre-update record `health preflight` wrote before the OS update says the
//! agent was healthy then. A factory-fresh device, or an agent that was
//! already down before the update, therefore never rolls an OS update back;
//! an OS that breaks a healthy activated agent does.

use crate::bsp;
use crate::cli::{HealthArgs, HealthCommand};
use crate::cmd::{lifecycle, policy};
use crate::contracts::encoding::now_timestamp;
use crate::contracts::registry::{LifecycleState, Outcome, Reason, ResultKind};
use crate::fsutil::{read_root_file, write_atomic};
use crate::paths::Paths;
use crate::results::{record, Report};
use crate::state::Records;
use crate::system::{Runner, SystemRunner};
use crate::variant::{BoardFile, ImageFacts, OsFacts};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

/// Bounded wait for the agent to leave `activating` (DEC-6.8).
const AGENT_WAIT: Duration = Duration::from_secs(90);
const AGENT_POLL: Duration = Duration::from_secs(3);

fn agent_active(runner: &dyn Runner, wait: Duration, poll: Duration) -> bool {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let state = runner
            .output("systemctl", &["is-active", "suderra-agent.service"])
            .map(|o| String::from_utf8_lossy(&o).trim().to_owned())
            .unwrap_or_default();
        match state.as_str() {
            "active" => return true,
            "activating" | "reloading" if std::time::Instant::now() < deadline => {
                std::thread::sleep(poll);
            }
            _ => return false,
        }
    }
}

/// The units lockdown ends: provisioning mode and the SSH server it runs
/// (`suderra-lockdown`, DEC-5.8).
const PROVISIONING_UNITS: [&str; 2] = ["suderra-provision-mode.service", "dropbear.service"];

fn unit_active(runner: &dyn Runner, unit: &str) -> bool {
    runner
        .output("systemctl", &["is-active", unit])
        .is_ok_and(|out| String::from_utf8_lossy(&out).trim() == "active")
}

/// Whether `target` is a mount point in the kernel's mount table (field 5 of
/// a `mountinfo` line); an unreadable table counts as not mounted.
fn mounted(paths: &Paths, target: &str) -> bool {
    read_root_file(&paths.proc_mountinfo(), 1 << 20)
        .ok()
        .flatten()
        .is_some_and(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .any(|line| line.split_whitespace().nth(4) == Some(target))
        })
}

/// A path to the device a technician can still use: provisioning mode or its
/// SSH server running, or the one-time-password shadow still bound over
/// `/etc/shadow`.
fn technician_path_open(paths: &Paths, runner: &dyn Runner) -> bool {
    PROVISIONING_UNITS
        .iter()
        .any(|unit| unit_active(runner, unit))
        || mounted(paths, "/etc/shadow")
}

/// The agent's own degraded flag (`/run/suderra/agent-health/health.json`
/// member `degraded`); an unreadable report counts as degraded.
fn agent_degraded(paths: &Paths) -> bool {
    match read_root_file(&paths.agent_health(), 64 * 1024) {
        Ok(Some(bytes)) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("degraded").and_then(serde_json::Value::as_bool))
            .unwrap_or(true),
        Ok(None) | Err(_) => true,
    }
}

/// `/data/rauc/pre-update.json` (DEC-6.8): the agent's health right before
/// an OS update, written by `health preflight` (suderra-ota install) and
/// removed by suderra-ota once that update is concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreUpdate {
    /// Lifecycle when the update started.
    pub lifecycle: LifecycleState,
    /// ACTIVE, agent active and not degraded.
    pub agent_healthy: bool,
    /// When it was recorded.
    pub recorded_at: String,
}

/// Reads the pre-update record; `None` when no OS update is pending.
pub(crate) fn pre_update(paths: &Paths) -> Result<Option<PreUpdate>> {
    let Some(bytes) = read_root_file(&paths.pre_update(), 4096)? else {
        return Ok(None);
    };
    crate::contracts::json::check_strict_object(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e}", paths.pre_update().display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is corrupt", paths.pre_update().display()))
        .map(Some)
}

/// Evaluates the predicate; the returned set is empty when healthy. `board`
/// is `None` on an image that declares no board: only the OS checks apply.
pub(crate) fn evaluate(
    paths: &Paths,
    os: &OsFacts,
    board: Option<&BoardFile>,
    runner: &dyn Runner,
    wait: Duration,
    poll: Duration,
    now: &str,
) -> Result<BTreeSet<Reason>> {
    let mut reasons = BTreeSet::new();
    if os.features.contains("verity")
        && std::fs::symlink_metadata(paths.dev_mapper().join("suderra-root")).is_err()
    {
        reasons.insert(Reason::VerityInactive);
    }
    if os.features.contains("luks")
        && std::fs::symlink_metadata(paths.dev_mapper().join("suderra-data")).is_err()
    {
        reasons.insert(Reason::DataMapperMissing);
    }
    if !policy::loaded_matches_record(paths, runner)? {
        reasons.insert(Reason::FirewallHashMismatch);
    }
    // The helper that owns the floor answers; one that cannot answer (it is
    // missing, or it fails) proves nothing, which is a failure too.
    if runner
        .output("suderra-time-state", &["floor-check"])
        .is_err()
    {
        reasons.insert(Reason::ClockBelowFloor);
    }
    if os.features.contains("tpm") && !bsp::tpm_reachable(paths) {
        reasons.insert(Reason::TpmUnavailable);
    }
    if !bsp::failed_probes(paths, os).is_empty() {
        reasons.insert(Reason::BspProbeFailed);
    }
    if board.is_none() {
        return Ok(reasons);
    }
    let abi_ok = |abi: u64| (os.compat.abi.0..=os.compat.abi.1).contains(&abi);
    let state = lifecycle::effective(paths, now);
    let receipt = Records::new(paths).receipt()?;
    match state {
        LifecycleState::Locked => {
            reasons.insert(Reason::LifecycleInconsistent);
        }
        LifecycleState::Active | LifecycleState::Maintenance => {
            let Some(receipt) = receipt.as_ref() else {
                reasons.insert(Reason::LifecycleInconsistent);
                return Ok(reasons);
            };
            if !abi_ok(receipt.agent_abi) {
                reasons.insert(Reason::AbiIncompatible);
            }
            if state == LifecycleState::Active && technician_path_open(paths, runner) {
                reasons.insert(Reason::LifecycleInconsistent);
            }
            let counted = pre_update(paths)?
                .is_some_and(|p| p.agent_healthy && p.lifecycle == LifecycleState::Active);
            if state == LifecycleState::Active && counted {
                if !agent_active(runner, wait, poll) {
                    reasons.insert(Reason::AgentNotActive);
                } else if agent_degraded(paths) {
                    reasons.insert(Reason::AgentDegraded);
                }
            }
        }
        LifecycleState::Factory | LifecycleState::Provisioning => {
            if receipt.as_ref().is_some_and(|r| !abi_ok(r.agent_abi)) {
                reasons.insert(Reason::AbiIncompatible);
            }
        }
        LifecycleState::Decommissioned | LifecycleState::Rma => {}
    }
    Ok(reasons)
}

/// Records the agent's health before an OS update (`health preflight`).
/// /data/rauc comes from the data layout; nothing is written when it is
/// missing (an unmounted /data).
pub(crate) fn preflight(
    paths: &Paths,
    runner: &dyn Runner,
    wait: Duration,
    poll: Duration,
    now: &str,
) -> Result<PreUpdate> {
    let dir = paths.rauc_state();
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
        bail!(
            "{} is missing: /data is not mounted or its layout is not applied",
            dir.display()
        );
    }
    let state = lifecycle::effective(paths, now);
    let agent_healthy = state == LifecycleState::Active
        && agent_active(runner, wait, poll)
        && !agent_degraded(paths);
    let record = PreUpdate {
        lifecycle: state,
        agent_healthy,
        recorded_at: now.to_owned(),
    };
    write_atomic(
        &paths.pre_update(),
        &serde_json::to_vec(&record)?,
        0o600,
        None,
    )?;
    Ok(record)
}

/// `suderra-installer health check|preflight`.
pub(crate) fn run(args: HealthArgs) -> Result<()> {
    let paths = Paths::system()?;
    match args.command {
        HealthCommand::Check => check(&paths),
        HealthCommand::Preflight => {
            let record = preflight(
                &paths,
                &SystemRunner,
                AGENT_WAIT,
                AGENT_POLL,
                &now_timestamp(),
            )?;
            println!("{}", serde_json::to_string(&record)?);
            Ok(())
        }
    }
}

fn check(paths: &Paths) -> Result<()> {
    let os = OsFacts::load(paths)?;
    let board = BoardFile::load(paths)?;
    let reasons = evaluate(
        paths,
        &os,
        board.as_ref(),
        &SystemRunner,
        AGENT_WAIT,
        AGENT_POLL,
        &now_timestamp(),
    )?;
    let mut named = reasons
        .iter()
        .map(|r| r.as_str().to_owned())
        .collect::<Vec<_>>()
        .join(" ");
    // bsp-probe-failed alone does not say which board support is missing.
    if reasons.contains(&Reason::BspProbeFailed) {
        named.push_str(&format!(
            " (probes failed: {})",
            bsp::failed_probes(paths, &os).join(" ")
        ));
    }
    // A typed result (result.schema.json) names the board; an image without
    // one reports through the exit status and the journal only.
    if let Some(board) = board {
        let facts = ImageFacts { os, board };
        let report = match reasons.iter().next() {
            None => Report::ok(ResultKind::HealthGate, None),
            Some(first) => Report::not_ok(ResultKind::HealthGate, Outcome::Alarm, *first)
                .with_detail(named.clone()),
        };
        record(paths, &facts, report)?;
    }
    if !reasons.is_empty() {
        bail!("health check failed: {named}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        build_delivery, image, receipt, write_binding, FakeRunner, Keys, Spec, BINDING_HEX,
    };

    const NOW: &str = "2026-10-20T12:00:00Z";

    fn reasons(paths: &Paths, facts: &ImageFacts, runner: &dyn Runner) -> BTreeSet<Reason> {
        evaluate(
            paths,
            &facts.os,
            Some(&facts.board),
            runner,
            Duration::ZERO,
            Duration::ZERO,
            NOW,
        )
        .unwrap()
    }

    fn apply_firewall(paths: &Paths, runner: &FakeRunner) {
        std::fs::write(paths.nft_appliance(), "flush ruleset\n").unwrap();
        policy::apply(paths, runner, NOW).unwrap();
    }

    #[test]
    fn a_factory_fresh_device_is_healthy_without_an_agent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let runner = FakeRunner {
            agent_state: "inactive".into(),
            ..FakeRunner::default()
        };
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        assert_eq!(
            reasons(&paths, &facts, &runner),
            BTreeSet::from([Reason::FirewallHashMismatch])
        );
        apply_firewall(&paths, &runner);
        assert!(reasons(&paths, &facts, &runner).is_empty());
    }

    #[test]
    fn locked_and_inconsistent_states_fail() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let runner = FakeRunner::default();
        assert!(reasons(&paths, &facts, &runner).contains(&Reason::LifecycleInconsistent));
        lifecycle::write(&paths, LifecycleState::Active, None).unwrap();
        assert!(
            reasons(&paths, &facts, &runner).contains(&Reason::LifecycleInconsistent),
            "ACTIVE without an install receipt"
        );
    }

    #[test]
    fn declared_features_must_be_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        std::fs::write(paths.features_file(), "FEATURES=\"verity luks\"\n").unwrap();
        let facts = ImageFacts::load(&paths).unwrap();
        let got = reasons(&paths, &facts, &FakeRunner::default());
        assert!(got.contains(&Reason::VerityInactive) && got.contains(&Reason::DataMapperMissing));
        std::fs::create_dir_all(paths.dev_mapper()).unwrap();
        std::fs::write(paths.dev_mapper().join("suderra-root"), "").unwrap();
        std::fs::write(paths.dev_mapper().join("suderra-data"), "").unwrap();
        let got = reasons(&paths, &facts, &FakeRunner::default());
        assert!(
            !got.contains(&Reason::VerityInactive) && !got.contains(&Reason::DataMapperMissing)
        );
    }

    /// A production image that declares no board (suderra_x86_64): RAUC and
    /// the gate, no lifecycle, no agent, no /etc/suderra/board.
    #[test]
    fn a_boardless_image_is_judged_on_its_os_checks_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        std::fs::remove_file(paths.board_file()).unwrap();
        std::fs::write(
            paths.features_file(),
            "FEATURES=\"verity luks secure-boot rauc\"\n",
        )
        .unwrap();
        let os = OsFacts::load(&paths).unwrap();
        assert!(BoardFile::load(&paths).unwrap().is_none());
        let runner = FakeRunner {
            agent_state: "inactive".into(),
            ..FakeRunner::default()
        };
        let judge = || {
            evaluate(
                &paths,
                &os,
                None,
                &runner,
                Duration::ZERO,
                Duration::ZERO,
                NOW,
            )
            .unwrap()
        };
        assert_eq!(
            judge(),
            BTreeSet::from([
                Reason::BspProbeFailed,
                Reason::DataMapperMissing,
                Reason::FirewallHashMismatch,
                Reason::VerityInactive,
            ])
        );
        std::fs::create_dir_all(paths.dev_mapper()).unwrap();
        std::fs::write(paths.dev_mapper().join("suderra-root"), "").unwrap();
        std::fs::write(paths.dev_mapper().join("suderra-data"), "").unwrap();
        // The firmware says Secure Boot is on: attributes, then the value 1.
        std::fs::create_dir_all(paths.secure_boot_variable().parent().unwrap()).unwrap();
        std::fs::write(paths.secure_boot_variable(), [6, 0, 0, 0, 1]).unwrap();
        apply_firewall(&paths, &runner);
        assert!(
            judge().is_empty(),
            "no lifecycle (LOCKED reading) and no agent on an image without a board"
        );
    }

    /// An ACTIVE device whose agent is down.
    fn active_device(tmp: &std::path::Path) -> (Paths, ImageFacts, FakeRunner) {
        let (paths, facts) = image(tmp);
        write_binding(&paths, BINDING_HEX);
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        let keys = Keys::new();
        let pins = keys.os_pins();
        let spec = Spec::default();
        let built = build_delivery(&keys, &spec);
        let artifact = tmp.join("artifact.tar.gz");
        std::fs::write(&artifact, &spec.artifact).unwrap();
        crate::cmd::edge::install_from_files(
            &paths,
            &facts,
            &pins,
            &built.delivery,
            &built.request,
            &artifact,
            NOW,
        )
        .unwrap();
        std::fs::create_dir_all(paths.agent_state()).unwrap();
        std::fs::write(
            paths.agent_state().join("activation-receipt.dsse"),
            receipt(&keys, &built.manifest),
        )
        .unwrap();
        assert_eq!(
            lifecycle::activate(&paths, &facts, &pins, NOW).unwrap(),
            LifecycleState::Active
        );
        let runner = FakeRunner {
            agent_state: "inactive".into(),
            ..FakeRunner::default()
        };
        apply_firewall(&paths, &runner);
        (paths, facts, runner)
    }

    #[test]
    fn the_agent_counts_only_when_it_was_healthy_before_the_update() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts, runner) = active_device(tmp.path());
        std::fs::create_dir_all(paths.rauc_state()).unwrap();

        // No OS update pending: the agent's state is not an OS verdict.
        assert!(reasons(&paths, &facts, &runner).is_empty());

        // The agent was already down before the update.
        let down = preflight(&paths, &runner, Duration::ZERO, Duration::ZERO, NOW).unwrap();
        assert!(!down.agent_healthy);
        assert!(reasons(&paths, &facts, &runner).is_empty());

        // It was healthy before the update and is down after it.
        let healthy = FakeRunner::default();
        std::fs::create_dir_all(paths.agent_health().parent().unwrap()).unwrap();
        std::fs::write(paths.agent_health(), r#"{"degraded":false}"#).unwrap();
        let before = preflight(&paths, &healthy, Duration::ZERO, Duration::ZERO, NOW).unwrap();
        assert_eq!(
            before,
            PreUpdate {
                lifecycle: LifecycleState::Active,
                agent_healthy: true,
                recorded_at: NOW.into(),
            }
        );
        assert_eq!(
            reasons(&paths, &facts, &runner),
            BTreeSet::from([Reason::AgentNotActive])
        );
        assert!(reasons(&paths, &facts, &healthy).is_empty());
        std::fs::write(paths.agent_health(), r#"{"degraded":true}"#).unwrap();
        assert_eq!(
            reasons(&paths, &facts, &healthy),
            BTreeSet::from([Reason::AgentDegraded])
        );
    }

    /// A runner in which exactly one unit is active.
    struct OneUnitActive {
        unit: &'static str,
        inner: FakeRunner,
    }

    impl Runner for OneUnitActive {
        fn output(&self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
            if let ("systemctl", ["is-active", unit]) = (program, args) {
                let state = if *unit == self.unit {
                    "active"
                } else {
                    "inactive"
                };
                return Ok(format!("{state}\n").into_bytes());
            }
            self.inner.output(program, args)
        }
    }

    #[test]
    fn a_clock_below_the_floor_fails_every_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let low = FakeRunner {
            clock_below_floor: true,
            ..FakeRunner::default()
        };
        apply_firewall(&paths, &low);
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        assert_eq!(
            reasons(&paths, &facts, &low),
            BTreeSet::from([Reason::ClockBelowFloor])
        );
        assert!(low
            .calls
            .borrow()
            .iter()
            .any(|call| call == "suderra-time-state floor-check"));
        assert!(reasons(&paths, &facts, &FakeRunner::default()).is_empty());
        // An image that declares no board is judged on the clock too.
        let boardless = evaluate(
            &paths,
            &facts.os,
            None,
            &low,
            Duration::ZERO,
            Duration::ZERO,
            NOW,
        )
        .unwrap();
        assert_eq!(boardless, BTreeSet::from([Reason::ClockBelowFloor]));
    }

    #[test]
    fn a_declared_tpm_that_does_not_answer_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let runner = FakeRunner::default();
        apply_firewall(&paths, &runner);
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        assert!(reasons(&paths, &facts, &runner).is_empty());
        std::fs::remove_file(paths.tpm_resource_manager()).unwrap();
        assert_eq!(
            reasons(&paths, &facts, &runner),
            BTreeSet::from([Reason::TpmUnavailable])
        );
        // An image that declares no TPM is not asked for one.
        std::fs::write(paths.features_file(), "FEATURES=\"\"\n").unwrap();
        let none = ImageFacts::load(&paths).unwrap();
        assert!(reasons(&paths, &none, &runner).is_empty());
    }

    #[test]
    fn declared_board_support_that_is_absent_fails_once_whatever_is_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        std::fs::write(
            paths.features_file(),
            "FEATURES=\"tpm rtc watchdog picontrol\"\n",
        )
        .unwrap();
        let facts = ImageFacts::load(&paths).unwrap();
        let runner = FakeRunner::default();
        apply_firewall(&paths, &runner);
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        assert_eq!(
            reasons(&paths, &facts, &runner),
            BTreeSet::from([Reason::BspProbeFailed])
        );
        std::fs::write(paths.picontrol_device(), "").unwrap();
        assert_eq!(bsp::failed_probes(&paths, &facts.os), ["rtc", "watchdog"]);
    }

    #[test]
    fn an_active_device_has_closed_its_technician_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts, runner) = active_device(tmp.path());
        assert!(reasons(&paths, &facts, &runner).is_empty());

        // The units suderra-lockdown ends, by name: the test must not read the constant it holds.
        for unit in ["suderra-provision-mode.service", "dropbear.service"] {
            let open = OneUnitActive {
                unit,
                inner: FakeRunner {
                    agent_state: "inactive".into(),
                    ..FakeRunner::default()
                },
            };
            assert_eq!(
                reasons(&paths, &facts, &open),
                BTreeSet::from([Reason::LifecycleInconsistent]),
                "{unit} still runs on an ACTIVE device"
            );
        }

        // The one-time-password shadow still bound over /etc/shadow.
        std::fs::create_dir_all(paths.proc_mountinfo().parent().unwrap()).unwrap();
        std::fs::write(
            paths.proc_mountinfo(),
            "26 1 8:3 / / rw - ext4 /dev/mapper/suderra-root ro\n\
             41 26 0:35 /otp-shadow /etc/shadow ro,relatime - tmpfs tmpfs rw\n",
        )
        .unwrap();
        assert_eq!(
            reasons(&paths, &facts, &runner),
            BTreeSet::from([Reason::LifecycleInconsistent])
        );
        std::fs::write(
            paths.proc_mountinfo(),
            "26 1 8:3 / / rw - ext4 /dev/mapper/suderra-root ro\n\
             42 26 0:36 / /etc/shadow-backup rw - tmpfs tmpfs rw\n",
        )
        .unwrap();
        assert!(
            reasons(&paths, &facts, &runner).is_empty(),
            "only /etc/shadow itself"
        );
    }

    #[test]
    fn a_device_still_in_provisioning_may_run_its_technician_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let open = FakeRunner {
            other_units_state: "active".into(),
            ..FakeRunner::default()
        };
        apply_firewall(&paths, &open);
        lifecycle::write(&paths, LifecycleState::Provisioning, None).unwrap();
        assert!(reasons(&paths, &facts, &open).is_empty());
    }

    #[test]
    fn preflight_writes_nothing_without_data_and_a_corrupt_record_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        assert!(preflight(
            &paths,
            &FakeRunner::default(),
            Duration::ZERO,
            Duration::ZERO,
            NOW
        )
        .is_err());
        assert!(!paths.pre_update().exists());

        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts, runner) = active_device(tmp.path());
        std::fs::create_dir_all(paths.rauc_state()).unwrap();
        std::fs::write(paths.pre_update(), r#"{"agent_healthy":true,"extra":1}"#).unwrap();
        assert!(evaluate(
            &paths,
            &facts.os,
            Some(&facts.board),
            &runner,
            Duration::ZERO,
            Duration::ZERO,
            NOW
        )
        .is_err());
    }
}
