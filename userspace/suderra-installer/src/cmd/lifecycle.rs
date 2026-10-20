// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Root-owned device lifecycle (ADR-048 DEC-5.8, DEC-5.14, DEC-12;
//! contracts lifecycle.json).
//!
//! The store `/data/suderra/os/lifecycle` has one writer, this module. A
//! missing, unknown or corrupt store reads LOCKED, the fail-safe appliance
//! state with the provisioning surface closed; it is never repaired
//! silently. PROVISIONING starts only on positive evidence: on production
//! images the `data-created` proof suderra-data-unlock writes on the boot
//! that formatted /data, on dev images (VARIANT=dev from the image) the
//! absence of a store. PROVISIONING → ACTIVE needs a root-verified
//! activation receipt; ACTIVE → MAINTENANCE a root-verified device-lifecycle
//! statement; MAINTENANCE returns to ACTIVE with a new receipt or when its
//! window ends.

use crate::cli::{LifecycleArgs, LifecycleCommand};
use crate::contracts::dsse::Envelope;
use crate::contracts::encoding::now_timestamp;
use crate::contracts::keys::KeyStore;
use crate::contracts::registry::{LifecycleState, Outcome, Reason, ResultKind, StatementType};
use crate::contracts::statements::{LifecycleAction, MaintenancePurpose};
use crate::contracts::verify::{verify_lifecycle, verify_receipt, Mode, Scope};
use crate::fsutil::{ensure_dir, read_root_file, read_untrusted_file, write_atomic};
use crate::paths::Paths;
use crate::results::{record, Report, Subject};
use crate::state::Records;
use crate::trust_anchors::load_os_pins;
use crate::variant::{ImageFacts, Variant};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Largest statement the agent may hand to root.
const MAX_STATEMENT: u64 = 64 * 1024;

/// The stored lifecycle record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleRecord {
    /// Stored state (never LOCKED: LOCKED is a reading, not a state).
    pub state: LifecycleState,
    /// When the state was entered.
    pub since: String,
    /// End of a MAINTENANCE window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_expires_at: Option<String>,
}

/// What the store reads as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    /// A valid record.
    Known(LifecycleRecord),
    /// No store.
    Missing,
    /// A store that does not parse or holds an impossible record.
    Corrupt(String),
}

impl Reading {
    /// The lifecycle state this reading means.
    pub(crate) fn state(&self) -> LifecycleState {
        match self {
            Reading::Known(r) => r.state,
            Reading::Missing | Reading::Corrupt(_) => LifecycleState::Locked,
        }
    }

    /// The state in force at `now`: a MAINTENANCE window whose end has
    /// passed is ACTIVE (lifecycle.json MAINTENANCE -> ACTIVE), whether or
    /// not `init` has recorded that transition yet, so an expired window
    /// never keeps the provisioning surface open.
    pub(crate) fn state_at(&self, now: &str) -> LifecycleState {
        match self {
            Reading::Known(r) if window_ended(r, now) => LifecycleState::Active,
            other => other.state(),
        }
    }
}

fn window_ended(r: &LifecycleRecord, now: &str) -> bool {
    r.state == LifecycleState::Maintenance
        && r.maintenance_expires_at
            .as_deref()
            .is_some_and(|end| now >= end)
}

/// The lifecycle state in force at `now` (see [`Reading::state_at`]).
pub(crate) fn effective(paths: &Paths, now: &str) -> LifecycleState {
    read(paths).state_at(now)
}

/// Path of the proof suderra-data-unlock writes on the boot that formatted
/// /data (DEC-12).
fn data_created(paths: &Paths) -> std::path::PathBuf {
    paths.run_os().join("data-created")
}

fn record_ok(r: &LifecycleRecord) -> bool {
    use crate::contracts::encoding::is_timestamp;
    r.state != LifecycleState::Locked
        && is_timestamp(&r.since)
        && match (&r.state, &r.maintenance_expires_at) {
            (LifecycleState::Maintenance, Some(t)) => is_timestamp(t),
            (LifecycleState::Maintenance, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        }
}

/// Reads the lifecycle store.
pub(crate) fn read(paths: &Paths) -> Reading {
    match read_root_file(&paths.lifecycle_store(), 4096) {
        Ok(None) => Reading::Missing,
        Ok(Some(bytes)) => {
            let parsed = crate::contracts::json::check_strict_object(&bytes)
                .map_err(|e| e.to_string())
                .and_then(|()| {
                    serde_json::from_slice::<LifecycleRecord>(&bytes).map_err(|e| e.to_string())
                });
            match parsed {
                Ok(r) if record_ok(&r) => Reading::Known(r),
                Ok(_) => Reading::Corrupt("impossible lifecycle record".into()),
                Err(e) => Reading::Corrupt(e),
            }
        }
        Err(e) => Reading::Corrupt(format!("{e:#}")),
    }
}

/// Mirrors the state read-only for the agent (/run/suderra/lifecycle).
fn mirror(paths: &Paths, state: LifecycleState) -> Result<()> {
    ensure_dir(&paths.run_suderra(), 0o750)?;
    if let Some(gid) = paths.agent_group() {
        std::os::unix::fs::chown(paths.run_suderra(), None, Some(gid.as_raw()))?;
    }
    write_atomic(
        &paths.run_suderra().join("lifecycle"),
        format!("{state}\n").as_bytes(),
        0o640,
        paths.agent_group(),
    )
}

/// Writes a new state and mirrors it.
pub(crate) fn write(
    paths: &Paths,
    state: LifecycleState,
    maintenance_expires_at: Option<String>,
) -> Result<()> {
    let record = LifecycleRecord {
        state,
        since: now_timestamp(),
        maintenance_expires_at,
    };
    if !record_ok(&record) {
        bail!("refusing to write an impossible lifecycle record");
    }
    paths.require_os_state()?;
    write_atomic(
        &paths.lifecycle_store(),
        &serde_json::to_vec(&record)?,
        0o600,
        None,
    )?;
    mirror(paths, state)
}

fn transition_report(from: LifecycleState, to: LifecycleState) -> Report {
    Report::ok(
        ResultKind::Lifecycle,
        Some(Subject {
            lifecycle_from: Some(from),
            lifecycle_to: Some(to),
            ..Subject::default()
        }),
    )
}

/// Creates the store as FACTORY on the boot that formatted /data
/// (suderra-data-unlock, DEC-12). It needs the data-created proof and never
/// replaces an existing store.
pub(crate) fn factory(paths: &Paths) -> Result<()> {
    if read_root_file(&data_created(paths), 4096)?.is_none() {
        bail!("no data-created evidence: /data was not formatted on this boot (DEC-12)");
    }
    match read(paths) {
        Reading::Missing => write(paths, LifecycleState::Factory, None),
        other => bail!("the lifecycle store already exists ({})", other.state()),
    }
}

fn locked_alarm(paths: &Paths, facts: &ImageFacts, why: String) -> Result<LifecycleState> {
    mirror(paths, LifecycleState::Locked)?;
    record(
        paths,
        facts,
        Report::not_ok(ResultKind::Lifecycle, Outcome::Alarm, Reason::StateCorrupt)
            .with_detail(why),
    )?;
    Ok(LifecycleState::Locked)
}

/// FACTORY -> PROVISIONING on positive evidence; the evidence is consumed
/// only once PROVISIONING is stored.
fn enter_provisioning(
    paths: &Paths,
    facts: &ImageFacts,
    stored: Option<LifecycleState>,
) -> Result<LifecycleState> {
    if facts.variant == Variant::Production && stored.is_none() {
        write(paths, LifecycleState::Factory, None)?;
    }
    write(paths, LifecycleState::Provisioning, None)?;
    if facts.variant == Variant::Production {
        std::fs::remove_file(data_created(paths))
            .context("cannot consume data-created evidence")?;
    }
    record(
        paths,
        facts,
        transition_report(LifecycleState::Factory, LifecycleState::Provisioning),
    )?;
    Ok(LifecycleState::Provisioning)
}

/// Boot-time and periodic evaluation (suderra-lifecycle.service, after
/// /data unlock): records the end of an expired MAINTENANCE window and the
/// FACTORY -> PROVISIONING entry, and mirrors the state for the agent.
pub(crate) fn init(paths: &Paths, facts: &ImageFacts, now: &str) -> Result<LifecycleState> {
    if !paths.os_state_available() {
        // An unmountable /data reads LOCKED in every variant, with an alarm
        // (DEC-12); suderra-data-unlock reports its own data-unlock result.
        return locked_alarm(
            paths,
            facts,
            "/data is not available, so the lifecycle store cannot be read".into(),
        );
    }
    let evidence = match facts.variant {
        Variant::Dev => true,
        Variant::Production => read_root_file(&data_created(paths), 4096)?.is_some(),
    };
    match read(paths) {
        Reading::Known(r) if window_ended(&r, now) => {
            write(paths, LifecycleState::Active, None)?;
            record(
                paths,
                facts,
                transition_report(LifecycleState::Maintenance, LifecycleState::Active),
            )?;
            Ok(LifecycleState::Active)
        }
        Reading::Known(r) if r.state == LifecycleState::Factory => {
            if evidence {
                return enter_provisioning(paths, facts, Some(LifecycleState::Factory));
            }
            // A FACTORY store on a later boot is a first boot cut off before
            // PROVISIONING; without fresh evidence it opens nothing.
            locked_alarm(
                paths,
                facts,
                "FACTORY store without data-created evidence: the first boot was interrupted (DEC-12)"
                    .into(),
            )
        }
        Reading::Known(r) => {
            mirror(paths, r.state)?;
            Ok(r.state)
        }
        Reading::Missing if evidence => enter_provisioning(paths, facts, None),
        Reading::Missing => locked_alarm(
            paths,
            facts,
            "lifecycle store missing without data-created evidence".into(),
        ),
        Reading::Corrupt(why) => locked_alarm(paths, facts, why),
    }
}

fn first(reasons: &std::collections::BTreeSet<Reason>) -> Reason {
    reasons
        .iter()
        .next()
        .copied()
        .unwrap_or(Reason::SchemaInvalid)
}

/// Root-verifies the agent's activation receipt and records ACTIVE (DEC-5.8).
pub(crate) fn activate(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    now: &str,
) -> Result<LifecycleState> {
    let from = read(paths).state();
    if !matches!(
        from,
        LifecycleState::Provisioning | LifecycleState::Maintenance
    ) {
        bail!("activation receipts are accepted only in PROVISIONING or MAINTENANCE, not {from}");
    }
    let path = paths.agent_state().join("activation-receipt.dsse");
    let bytes = read_untrusted_file(&path, MAX_STATEMENT)?
        .with_context(|| format!("{} does not exist", path.display()))?;
    let records = Records::new(paths);
    let device = records.device_record(facts)?;
    let scope = Scope {
        os_keys: keys,
        device: Some(&device),
        now,
        mode: Mode::Accept,
    };
    let env = match Envelope::parse(&bytes) {
        Ok(env) => env,
        Err(reason) => {
            record(
                paths,
                facts,
                Report::not_ok(ResultKind::Lifecycle, Outcome::Rejected, reason),
            )?;
            bail!("activation receipt rejected: {reason}");
        }
    };
    let receipt = match verify_receipt(&env, &scope).accepted() {
        Ok(v) => v,
        Err(reasons) => {
            let reason = first(&reasons);
            record(
                paths,
                facts,
                Report::not_ok(ResultKind::Lifecycle, Outcome::Rejected, reason).with_subject(
                    Subject::statement(
                        StatementType::EdgeActivationReceipt,
                        &env.statement_digest(),
                    ),
                ),
            )?;
            bail!("activation receipt rejected: {reason}");
        }
    };
    // The floor rises only once the installed release has proven itself:
    // the receipt is the cloud's proof of the agent's first authenticated
    // MQTT session (DEC-2.5, DEC-5.7).
    let installed = records
        .receipt()?
        .context("no install receipt: nothing was installed to activate")?;
    records.raise_floor(installed.security_version)?;
    write(paths, LifecycleState::Active, None)?;
    let mut report = transition_report(from, LifecycleState::Active);
    if let Some(subject) = report.subject.as_mut() {
        subject.statement_type = Some(StatementType::EdgeActivationReceipt.as_str().to_owned());
        subject.statement_digest = Some(crate::contracts::statements::Digest {
            sha256: receipt.digest.clone(),
        });
    }
    record(paths, facts, report)?;
    Ok(LifecycleState::Active)
}

/// Root-verifies a device-lifecycle statement from the agent and performs
/// the transition (P0: enter-maintenance for reprovisioning).
pub(crate) fn request(
    paths: &Paths,
    facts: &ImageFacts,
    keys: &KeyStore,
    now: &str,
) -> Result<LifecycleState> {
    let from = effective(paths, now);
    if from != LifecycleState::Active {
        bail!("lifecycle requests are accepted only in ACTIVE, not {from}");
    }
    let path = paths.agent_state().join("lifecycle-request.dsse");
    let bytes = read_untrusted_file(&path, MAX_STATEMENT)?
        .with_context(|| format!("{} does not exist", path.display()))?;
    let records = Records::new(paths);
    let device = records.device_record(facts)?;
    let scope = Scope {
        os_keys: keys,
        device: Some(&device),
        now,
        mode: Mode::Accept,
    };
    let env = match Envelope::parse(&bytes) {
        Ok(env) => env,
        Err(reason) => {
            record(
                paths,
                facts,
                Report::not_ok(ResultKind::Lifecycle, Outcome::Rejected, reason),
            )?;
            bail!("lifecycle request rejected: {reason}");
        }
    };
    let statement = match verify_lifecycle(&env, &scope).accepted() {
        Ok(v) => v,
        Err(reasons) => {
            let reason = first(&reasons);
            record(
                paths,
                facts,
                Report::not_ok(ResultKind::Lifecycle, Outcome::Rejected, reason).with_subject(
                    Subject::statement(StatementType::DeviceLifecycle, &env.statement_digest()),
                ),
            )?;
            bail!("lifecycle request rejected: {reason}");
        }
    };
    let s = &statement.statement;
    if s.action != LifecycleAction::EnterMaintenance
        || s.purpose != Some(MaintenancePurpose::Reprovision)
    {
        // Decommission, RMA and break-glass need physical presence (P3).
        bail!("only enter-maintenance for reprovision is implemented in P0");
    }
    records.write_accepted(
        StatementType::DeviceLifecycle,
        Some(s.update_seq),
        &statement.digest,
    )?;
    write(
        paths,
        LifecycleState::Maintenance,
        Some(s.expires_at.clone()),
    )?;
    let mut report = transition_report(from, LifecycleState::Maintenance);
    if let Some(subject) = report.subject.as_mut() {
        subject.statement_type = Some(StatementType::DeviceLifecycle.as_str().to_owned());
        subject.statement_digest = Some(crate::contracts::statements::Digest {
            sha256: statement.digest.clone(),
        });
        subject.update_seq = Some(s.update_seq);
    }
    record(paths, facts, report)?;
    Ok(LifecycleState::Maintenance)
}

/// `suderra-installer lifecycle <command>`.
pub(crate) fn run(args: LifecycleArgs) -> Result<()> {
    let paths = Paths::system()?;
    let now = now_timestamp();
    match args.command {
        LifecycleCommand::Status => {
            println!("{}", effective(&paths, &now));
            Ok(())
        }
        LifecycleCommand::Factory => {
            factory(&paths)?;
            println!("{}", LifecycleState::Factory);
            Ok(())
        }
        LifecycleCommand::Init => {
            let facts = ImageFacts::load(&paths)?;
            let state = init(&paths, &facts, &now)?;
            println!("{state}");
            Ok(())
        }
        LifecycleCommand::Activate => {
            let facts = ImageFacts::load(&paths)?;
            let keys = load_os_pins(&paths, facts.pin_policy())?;
            println!("{}", activate(&paths, &facts, &keys, &now)?);
            Ok(())
        }
        LifecycleCommand::Request => {
            let facts = ImageFacts::load(&paths)?;
            let keys = load_os_pins(&paths, facts.pin_policy())?;
            println!("{}", request(&paths, &facts, &keys, &now)?);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::image;

    const NOW: &str = "2026-10-20T12:00:00Z";

    fn production(root: &std::path::Path) -> (Paths, ImageFacts) {
        let (paths, _) = image(root);
        let text = std::fs::read_to_string(paths.os_release())
            .unwrap()
            .replace("VARIANT=dev", "VARIANT=prod");
        std::fs::write(paths.os_release(), text).unwrap();
        let facts = ImageFacts::load(&paths).unwrap();
        assert_eq!(facts.variant, Variant::Production);
        (paths, facts)
    }

    fn mirrored(paths: &Paths) -> String {
        std::fs::read_to_string(paths.run_suderra().join("lifecycle")).unwrap()
    }

    #[test]
    fn dev_images_enter_provisioning_without_a_store() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        assert_eq!(
            init(&paths, &facts, NOW).unwrap(),
            LifecycleState::Provisioning
        );
        assert_eq!(mirrored(&paths), "PROVISIONING\n");
        assert_eq!(
            init(&paths, &facts, NOW).unwrap(),
            LifecycleState::Provisioning,
            "idempotent"
        );
    }

    #[test]
    fn production_needs_data_created_evidence() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = production(tmp.path());
        assert_eq!(init(&paths, &facts, NOW).unwrap(), LifecycleState::Locked);
        assert_eq!(mirrored(&paths), "LOCKED\n");
        assert_eq!(
            read(&paths),
            Reading::Missing,
            "LOCKED is a reading, never stored"
        );

        std::fs::create_dir_all(paths.run_os()).unwrap();
        std::fs::write(paths.run_os().join("data-created"), "").unwrap();
        assert_eq!(
            init(&paths, &facts, NOW).unwrap(),
            LifecycleState::Provisioning
        );
        assert!(
            !paths.run_os().join("data-created").exists(),
            "the evidence is consumed"
        );
    }

    #[test]
    fn a_corrupt_store_reads_locked_and_is_never_rewritten() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        std::fs::create_dir_all(paths.os_state()).unwrap();
        for corrupt in [
            "not json",
            r#"{"state":"LOCKED","since":"2026-10-20T00:00:00Z"}"#,
            r#"{"state":"MAINTENANCE","since":"2026-10-20T00:00:00Z"}"#,
            r#"{"state":"ACTIVE","since":"2026-10-20T00:00:00Z","extra":1}"#,
        ] {
            std::fs::write(paths.lifecycle_store(), corrupt).unwrap();
            assert_eq!(
                init(&paths, &facts, NOW).unwrap(),
                LifecycleState::Locked,
                "{corrupt}"
            );
            assert_eq!(
                std::fs::read_to_string(paths.lifecycle_store()).unwrap(),
                corrupt
            );
        }
    }

    #[test]
    fn an_unavailable_data_partition_reads_locked_in_every_variant() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        std::fs::remove_dir(paths.os_state()).unwrap();
        assert_eq!(facts.variant, Variant::Dev);
        assert_eq!(init(&paths, &facts, NOW).unwrap(), LifecycleState::Locked);
        assert_eq!(mirrored(&paths), "LOCKED\n");
        assert!(!paths.os_state().exists(), "nothing is created under /data");
    }

    #[test]
    fn the_factory_store_of_data_unlock_enters_provisioning() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = production(tmp.path());
        assert!(
            factory(&paths).is_err(),
            "FACTORY needs data-created evidence"
        );
        std::fs::create_dir_all(paths.run_os()).unwrap();
        std::fs::write(paths.run_os().join("data-created"), "").unwrap();
        factory(&paths).unwrap();
        assert_eq!(read(&paths).state(), LifecycleState::Factory);
        assert!(
            factory(&paths).is_err(),
            "an existing store is never replaced"
        );
        assert_eq!(
            init(&paths, &facts, NOW).unwrap(),
            LifecycleState::Provisioning
        );
        assert_eq!(mirrored(&paths), "PROVISIONING\n");
        assert!(!paths.run_os().join("data-created").exists());
    }

    #[test]
    fn a_factory_store_without_fresh_evidence_opens_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = production(tmp.path());
        write(&paths, LifecycleState::Factory, None).unwrap();
        assert_eq!(init(&paths, &facts, NOW).unwrap(), LifecycleState::Locked);
        assert_eq!(mirrored(&paths), "LOCKED\n");
        assert_eq!(
            read(&paths).state(),
            LifecycleState::Factory,
            "store untouched"
        );
    }

    #[test]
    fn an_ended_window_is_active_before_init_records_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _) = image(tmp.path());
        write(
            &paths,
            LifecycleState::Maintenance,
            Some("2026-10-21T00:00:00Z".into()),
        )
        .unwrap();
        assert_eq!(effective(&paths, NOW), LifecycleState::Maintenance);
        assert_eq!(
            effective(&paths, "2026-10-21T00:00:00Z"),
            LifecycleState::Active
        );
        assert_eq!(read(&paths).state(), LifecycleState::Maintenance);
    }

    #[test]
    fn maintenance_ends_with_its_window() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        write(
            &paths,
            LifecycleState::Maintenance,
            Some("2026-10-21T00:00:00Z".into()),
        )
        .unwrap();
        assert_eq!(
            init(&paths, &facts, NOW).unwrap(),
            LifecycleState::Maintenance
        );
        assert_eq!(
            init(&paths, &facts, "2026-10-21T00:00:00Z").unwrap(),
            LifecycleState::Active
        );
    }
}
