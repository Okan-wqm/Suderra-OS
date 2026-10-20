// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer health check`: the OS and agent predicate of the
//! health gate (ADR-048 DEC-6.8, DEC-23).
//!
//! It does not depend on RAUC and runs on every image; the RAUC health gate
//! calls it before mark-good. The features it checks come from the image's
//! build-time declaration (`/etc/suderra/board` FEATURES), not from probing,
//! so an absent declared feature is a failure. The agent counts only once the
//! lifecycle is ACTIVE (a root-verified activation receipt), so a
//! factory-fresh device never rolls back an OS update over a missing agent.

use crate::cli::HealthArgs;
use crate::cmd::{lifecycle, policy};
use crate::contracts::encoding::now_timestamp;
use crate::contracts::registry::{LifecycleState, Outcome, Reason, ResultKind};
use crate::fsutil::read_root_file;
use crate::paths::Paths;
use crate::results::{record, Report};
use crate::state::Records;
use crate::system::{Runner, SystemRunner};
use crate::variant::ImageFacts;
use anyhow::{bail, Result};
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

/// Evaluates the predicate; the returned set is empty when healthy.
pub(crate) fn evaluate(
    paths: &Paths,
    facts: &ImageFacts,
    runner: &dyn Runner,
    wait: Duration,
    poll: Duration,
    now: &str,
) -> Result<BTreeSet<Reason>> {
    let mut reasons = BTreeSet::new();
    let features = &facts.board.features;
    if features.contains("verity")
        && std::fs::symlink_metadata(paths.dev_mapper().join("suderra-root")).is_err()
    {
        reasons.insert(Reason::VerityInactive);
    }
    if features.contains("luks")
        && std::fs::symlink_metadata(paths.dev_mapper().join("suderra-data")).is_err()
    {
        reasons.insert(Reason::DataMapperMissing);
    }
    match policy::loaded_ruleset_hash(runner) {
        Ok(hash) if policy::recorded_hash(paths)?.as_deref() == Some(hash.as_str()) => {}
        _ => {
            reasons.insert(Reason::FirewallHashMismatch);
        }
    }
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
            if receipt.agent_abi < facts.compat.abi.0 || receipt.agent_abi > facts.compat.abi.1 {
                reasons.insert(Reason::AbiIncompatible);
            }
            if state == LifecycleState::Active {
                if !agent_active(runner, wait, poll) {
                    reasons.insert(Reason::AgentNotActive);
                } else if agent_degraded(paths) {
                    reasons.insert(Reason::AgentDegraded);
                }
            }
        }
        LifecycleState::Factory | LifecycleState::Provisioning => {
            if let Some(receipt) = receipt.as_ref() {
                if receipt.agent_abi < facts.compat.abi.0 || receipt.agent_abi > facts.compat.abi.1
                {
                    reasons.insert(Reason::AbiIncompatible);
                }
            }
        }
        LifecycleState::Decommissioned | LifecycleState::Rma => {}
    }
    Ok(reasons)
}

/// `suderra-installer health check`.
pub(crate) fn run(_args: HealthArgs) -> Result<()> {
    let paths = Paths::system()?;
    let facts = ImageFacts::load(&paths)?;
    let reasons = evaluate(
        &paths,
        &facts,
        &SystemRunner,
        AGENT_WAIT,
        AGENT_POLL,
        &now_timestamp(),
    )?;
    if reasons.is_empty() {
        record(&paths, &facts, Report::ok(ResultKind::HealthGate, None))?;
        return Ok(());
    }
    let names: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
    let first = *reasons
        .iter()
        .next()
        .unwrap_or(&Reason::LifecycleInconsistent);
    record(
        &paths,
        &facts,
        Report::not_ok(ResultKind::HealthGate, Outcome::Alarm, first).with_detail(names.join(" ")),
    )?;
    bail!("health check failed: {}", names.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{image, FakeRunner};

    const NOW: &str = "2026-10-20T12:00:00Z";

    fn reasons(paths: &Paths, facts: &ImageFacts, runner: &FakeRunner) -> BTreeSet<Reason> {
        evaluate(paths, facts, runner, Duration::ZERO, Duration::ZERO, NOW).unwrap()
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
        std::fs::create_dir_all(tmp.path().join("etc")).unwrap();
        std::fs::write(paths.nft_appliance(), "flush ruleset\n").unwrap();
        policy::apply(&paths, &runner, NOW).unwrap();
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
        std::fs::write(
            paths.board_file(),
            "BOARD_PROFILE=revpi-connect4\nARCH=aarch64\nFEATURES=\"verity luks\"\n",
        )
        .unwrap();
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
}
