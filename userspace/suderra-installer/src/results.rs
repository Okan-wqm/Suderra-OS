// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed install and update results (ADR-048 DEC-27; contracts
//! schemas/result.schema.json).
//!
//! Root writes every result to `/data/suderra/os/results/` (kept across
//! boots) and mirrors it under `/run/suderra/results/` (root:suderra 0750,
//! files 0640) for the agent to publish. A result is validated against the
//! schema before it is written, so an invalid result cannot be produced.

use crate::contracts::encoding::{
    is_os_version, is_reason_code, is_semver, is_statement_type_name, is_timestamp, now_timestamp,
};
#[cfg(test)]
use crate::contracts::json::check_strict_object;
use crate::contracts::json::MAX_SAFE_INTEGER;
use crate::contracts::registry::{
    BoardProfile, LifecycleState, Outcome, Reason, ResultKind, StatementType, TimeState,
};
use crate::contracts::statements::{present, Digest};
use crate::fsutil::{ensure_dir, read_root_file, write_atomic};
use crate::paths::Paths;
use crate::variant::ImageFacts;
use anyhow::{bail, Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

/// `_type` of a result document.
pub(crate) const RESULT_TYPE: &str = "suderra.result.v1";
/// Results kept under /data/suderra/os/results.
const RETAINED: usize = 256;
/// A result document is a few hundred bytes (`detail` is at most 512); the
/// agent's reader takes no more than this from a file (sens-api-gateway
/// src/results.rs `MAX_RESULT_BYTES`).
const MAX_RESULT_BYTES: u64 = 16 * 1024;

/// result.schema.json `subject`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Subject {
    /// Release version.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub version: Option<String>,
    /// Release security_version.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub security_version: Option<u64>,
    /// Statement type the result is about.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub statement_type: Option<String>,
    /// Its statement digest.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub statement_digest: Option<Digest>,
    /// Its sequence value.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub update_seq: Option<u64>,
    /// Lifecycle state before.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub lifecycle_from: Option<LifecycleState>,
    /// Lifecycle state after.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub lifecycle_to: Option<LifecycleState>,
}

impl Subject {
    /// A subject naming one statement.
    pub(crate) fn statement(statement_type: StatementType, digest: &str) -> Self {
        Self {
            statement_type: Some(statement_type.as_str().to_owned()),
            statement_digest: Some(Digest {
                sha256: digest.to_owned(),
            }),
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn validate(&self) -> Result<(), String> {
        if self.is_empty() {
            return Err("subject must have at least one member".into());
        }
        if self.version.as_deref().is_some_and(|v| !is_semver(v)) {
            return Err("subject.version".into());
        }
        if self
            .security_version
            .is_some_and(|v| v > u64::from(u32::MAX))
        {
            return Err("subject.security_version".into());
        }
        if self
            .statement_type
            .as_deref()
            .is_some_and(|t| !is_statement_type_name(t))
        {
            return Err("subject.statement_type".into());
        }
        if self
            .statement_digest
            .as_ref()
            .is_some_and(|d| !crate::contracts::encoding::is_sha256_hex(&d.sha256))
        {
            return Err("subject.statement_digest".into());
        }
        if self
            .update_seq
            .is_some_and(|s| !(1..=MAX_SAFE_INTEGER).contains(&s))
        {
            return Err("subject.update_seq".into());
        }
        Ok(())
    }
}

/// suderra.result.v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultDocument {
    #[serde(rename = "_type")]
    type_: String,
    /// Monotonic per device.
    pub seq: u64,
    /// What the result is about.
    pub kind: ResultKind,
    /// How it ended.
    pub outcome: Outcome,
    /// Reason code (absent exactly when outcome is ok).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub reason: Option<String>,
    /// When it happened.
    pub occurred_at: String,
    /// Clock trust at occurred_at.
    pub time_state: TimeState,
    /// Board.
    pub board_profile: BoardProfile,
    /// OS version.
    pub os_version: String,
    /// What it refers to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub subject: Option<Subject>,
    /// Free text for operators (never parsed by the cloud).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub detail: Option<String>,
}

impl ResultDocument {
    /// Every schema constraint serde does not enforce.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.type_ != RESULT_TYPE {
            return Err("_type".into());
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.seq) {
            return Err("seq".into());
        }
        match (&self.outcome, &self.reason) {
            (Outcome::Ok, None) => {}
            (Outcome::Ok, Some(_)) => return Err("an ok result carries no reason".into()),
            (_, None) => return Err("a non-ok result carries a reason".into()),
            (_, Some(reason)) => {
                if !is_reason_code(reason) {
                    return Err("reason form".into());
                }
                let allowed = Reason::parse(reason).is_some_and(|r| self.kind.allows(r));
                if !allowed {
                    return Err(format!("{reason} is not a {} reason", self.kind));
                }
            }
        }
        if !is_timestamp(&self.occurred_at) {
            return Err("occurred_at".into());
        }
        if !is_os_version(&self.os_version) {
            return Err("os_version".into());
        }
        if let Some(subject) = &self.subject {
            subject.validate()?;
        }
        // A result that concludes a request names the statement it concludes:
        // that digest is what settles the request (channels.json settlement).
        if self.kind.names_its_statement() {
            let names_statement = self
                .subject
                .as_ref()
                .is_some_and(|s| s.statement_type.is_some() && s.statement_digest.is_some());
            if !names_statement {
                return Err(format!(
                    "a {} result names its statement in subject.statement_type and subject.statement_digest",
                    self.kind
                ));
            }
        }
        if self
            .detail
            .as_deref()
            .is_some_and(|d| d.chars().count() > 512)
        {
            return Err("detail longer than 512 characters".into());
        }
        Ok(())
    }

    /// Parses and validates a document root's own writer stored.
    fn from_stored(bytes: &[u8]) -> Result<Self, String> {
        let doc: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        doc.validate()?;
        Ok(doc)
    }

    /// Parses a result document (golden documents).
    #[cfg(test)]
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Reason> {
        check_strict_object(bytes).map_err(|_| Reason::PayloadJsonInvalid)?;
        let doc: Self = serde_json::from_slice(bytes).map_err(|_| Reason::SchemaInvalid)?;
        doc.validate().map_err(|_| Reason::SchemaInvalid)?;
        Ok(doc)
    }
}

/// What a caller reports; the writer adds seq, time and image facts.
#[derive(Debug, Clone)]
pub(crate) struct Report {
    /// Kind.
    pub kind: ResultKind,
    /// Outcome.
    pub outcome: Outcome,
    /// Reason (required unless ok).
    pub reason: Option<Reason>,
    /// Subject.
    pub subject: Option<Subject>,
    /// Operator detail.
    pub detail: Option<String>,
}

impl Report {
    /// An ok report.
    pub(crate) fn ok(kind: ResultKind, subject: Option<Subject>) -> Self {
        Self {
            kind,
            outcome: Outcome::Ok,
            reason: None,
            subject,
            detail: None,
        }
    }

    /// A non-ok report.
    pub(crate) fn not_ok(kind: ResultKind, outcome: Outcome, reason: Reason) -> Self {
        Self {
            kind,
            outcome,
            reason: Some(reason),
            subject: None,
            detail: None,
        }
    }

    /// Adds operator detail, truncated to the schema bound.
    pub(crate) fn with_detail(mut self, detail: impl Into<String>) -> Self {
        let detail: String = detail.into().chars().take(512).collect();
        self.detail = Some(detail);
        self
    }

    /// Sets the subject.
    pub(crate) fn with_subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }
}

/// Clock trust published by the time-state helper (DEC-7.3): the state of a
/// conforming, fresh document, and `unsynced` for anything else
/// (`time_state.rs`).
fn time_state(paths: &Paths) -> TimeState {
    crate::time_state::read(paths, chrono::Utc::now())
}

/// Writes one result and returns the document.
///
/// With /data available the result is numbered by the persistent counter,
/// kept in /data/suderra/os/results and mirrored to /run/suderra/results.
/// Without it (unmounted or its layout not applied: the data-unlock and
/// LOCKED alarms of DEC-12) nothing can persist, so the result is numbered
/// by a per-boot counter under /run/suderra-os and written to
/// /run/suderra/results only, as `volatile-<seq>-<kind>.json`, a name that
/// never collides with a persistent result.
pub(crate) fn record(paths: &Paths, facts: &ImageFacts, report: Report) -> Result<ResultDocument> {
    let persistent = paths.os_state_available();
    let counter_dir = if persistent {
        paths.results_store()
    } else {
        ensure_dir(&paths.run_os(), 0o700)?;
        paths.run_os().join("results")
    };
    ensure_dir(&counter_dir, 0o700)?;
    let _lock = lock_results(&counter_dir)?;

    let seq_path = counter_dir.join("seq");
    let last = match read_root_file(&seq_path, 32)? {
        Some(bytes) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|t| t.trim().parse::<u64>().ok())
            .context("results seq is corrupt")?,
        None => 0,
    };
    let seq = last + 1;
    let doc = ResultDocument {
        type_: RESULT_TYPE.to_owned(),
        seq,
        kind: report.kind,
        outcome: report.outcome,
        reason: report.reason.map(|r| r.as_str().to_owned()),
        occurred_at: now_timestamp(),
        time_state: time_state(paths),
        board_profile: facts.board.board,
        os_version: facts.os.os_version.clone(),
        subject: report.subject,
        detail: report.detail,
    };
    if let Err(e) = doc.validate() {
        bail!("refusing to write an invalid result: {e}");
    }
    let bytes = serde_json::to_vec(&doc)?;
    let name = if persistent {
        format!("{seq:016}-{}.json", doc.kind)
    } else {
        format!("volatile-{seq:016}-{}.json", doc.kind)
    };
    write_atomic(&seq_path, format!("{seq}\n").as_bytes(), 0o600, None)?;
    if persistent {
        write_atomic(&counter_dir.join(&name), &bytes, 0o600, None)?;
        prune(&counter_dir)?;
    }

    let run = ensure_run_results(paths)?;
    write_atomic(&run.join(&name), &bytes, 0o640, paths.agent_group())?;
    prune(&run)?;
    Ok(doc)
}

/// Takes the exclusive lock that orders every writer of one result directory
/// (the counter, the files and the pruning).
fn lock_results(counter_dir: &std::path::Path) -> Result<Flock<std::fs::File>> {
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(crate::fsutil::libc_flags::O_NOFOLLOW)
        .open(counter_dir.join(".lock"))
        .context("cannot open the results lock")?;
    Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| anyhow::anyhow!("cannot lock results: {errno}"))
}

/// `/run/suderra/results`, root:suderra 0750 as systemd-tmpfiles declares it
/// (usr/lib/tmpfiles.d/suderra.conf), created when it is missing.
fn ensure_run_results(paths: &Paths) -> Result<std::path::PathBuf> {
    let run = paths.run_results();
    ensure_dir(&paths.run_suderra(), 0o750)?;
    ensure_dir(&run, 0o750)?;
    if let Some(gid) = paths.agent_group() {
        std::os::unix::fs::chown(paths.run_suderra(), None, Some(gid.as_raw()))
            .context("cannot chgrp /run/suderra")?;
        std::os::unix::fs::chown(&run, None, Some(gid.as_raw()))
            .context("cannot chgrp /run/suderra/results")?;
    }
    Ok(run)
}

/// A persistent result's file name, `<seq, 16 digits>-<kind>.json`
/// (channels.json result_telemetry `file_name_pattern` without the `volatile-`
/// form, which exists only under /run).
fn is_result_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let Some((digits, kind)) = stem.split_at_checked(16) else {
        return false;
    };
    let Some(kind) = kind.strip_prefix('-') else {
        return false;
    };
    digits.bytes().all(|b| b.is_ascii_digit())
        && !kind.is_empty()
        && kind.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// What [`mirror`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Mirrored {
    /// Results written to /run/suderra/results (new, or different from the
    /// persistent copy).
    pub restored: usize,
    /// Persistent files named like a result that are not one (unreadable, not a
    /// valid document, or a document whose seq or kind disagrees with its name).
    pub skipped: Vec<String>,
}

/// Restores the agent's view of the persistent results after a boot.
///
/// /run/suderra/results is a tmpfs: a reboot empties it while the results stay
/// in /data/suderra/os/results. The agent republishes what is in the directory
/// until the broker acknowledged it and keeps only the highest acknowledged seq,
/// so a result written just before a reboot (a lockdown, a rollback, an alarm)
/// that the broker had not acknowledged would otherwise never reach the cloud,
/// and a newer result published first would move the cursor past it for good. The
/// persistent copy is the truth: a mirrored file that differs is replaced. Only
/// the newest [`RETAINED`] results are mirrored, as `record` keeps them.
///
/// Without /data (unmounted, or its layout not applied) there is nothing
/// persistent to restore, and the volatile results already in /run stay.
pub(crate) fn mirror(paths: &Paths) -> Result<Mirrored> {
    let store = paths.results_store();
    let mut done = Mirrored::default();
    if !paths.os_state_available() || !store.is_dir() {
        return Ok(done);
    }
    let _lock = lock_results(&store)?;
    let mut names: Vec<String> = std::fs::read_dir(&store)
        .with_context(|| format!("cannot read {}", store.display()))?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| is_result_file_name(n))
        .collect();
    names.sort();
    let newest = names.split_off(names.len().saturating_sub(RETAINED));
    let run = ensure_run_results(paths)?;
    for name in newest {
        let stored = read_root_file(&store.join(&name), MAX_RESULT_BYTES)
            .ok()
            .flatten()
            .filter(|bytes| {
                ResultDocument::from_stored(bytes)
                    .is_ok_and(|doc| format!("{:016}-{}.json", doc.seq, doc.kind) == name)
            });
        let Some(bytes) = stored else {
            tracing::error!(
                "{name} in {} is not a result: not mirrored",
                store.display()
            );
            done.skipped.push(name);
            continue;
        };
        if read_root_file(&run.join(&name), MAX_RESULT_BYTES)
            .ok()
            .flatten()
            .as_deref()
            != Some(bytes.as_slice())
        {
            write_atomic(&run.join(&name), &bytes, 0o640, paths.agent_group())?;
            done.restored += 1;
        }
    }
    prune(&run)?;
    Ok(done)
}

/// Keeps the newest [`RETAINED`] result files of `dir` (names sort by seq;
/// volatile results sort after persistent ones and go last).
fn prune(dir: &std::path::Path) -> Result<()> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
        .collect();
    names.sort();
    let excess = names.len().saturating_sub(RETAINED);
    for name in names.into_iter().take(excess) {
        std::fs::remove_file(dir.join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::image;

    #[test]
    fn results_are_schema_valid_and_monotonic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let first = record(&paths, &facts, Report::ok(ResultKind::EdgeInstall, None)).unwrap();
        let second = record(
            &paths,
            &facts,
            Report::not_ok(
                ResultKind::VerifyCurrent,
                Outcome::Rejected,
                Reason::CurrentLinkMismatch,
            )
            .with_detail("x".repeat(600)),
        )
        .unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
        let mirrored = std::fs::read(
            paths
                .run_results()
                .join("0000000000000002-verify-current.json"),
        )
        .unwrap();
        assert_eq!(ResultDocument::parse(&mirrored).unwrap(), second);
        let kept = std::fs::read(
            paths
                .results_store()
                .join("0000000000000001-edge-install.json"),
        )
        .unwrap();
        assert_eq!(ResultDocument::parse(&kept).unwrap(), first);
    }

    #[test]
    fn without_data_a_result_is_volatile_and_written_only_to_run() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        std::fs::remove_dir(paths.os_state()).unwrap();
        let doc = record(
            &paths,
            &facts,
            Report::not_ok(
                ResultKind::DataUnlock,
                Outcome::Alarm,
                Reason::DataUnmountable,
            ),
        )
        .unwrap();
        assert_eq!(doc.seq, 1);
        assert!(!paths.os_state().exists(), "nothing is created under /data");
        let mirrored = std::fs::read(
            paths
                .run_results()
                .join("volatile-0000000000000001-data-unlock.json"),
        )
        .unwrap();
        assert_eq!(ResultDocument::parse(&mirrored).unwrap(), doc);
    }

    /// What a reboot does to the agent's view: /run is a tmpfs, so every mirrored
    /// file is gone while the persistent store is untouched.
    fn reboot(paths: &Paths) {
        for entry in std::fs::read_dir(paths.run_results()).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
    }

    fn run_names(paths: &Paths) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(paths.run_results())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_reboot_does_not_hide_results_the_agent_has_not_published() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        for kind in [
            ResultKind::EdgeInstall,
            ResultKind::Lockdown,
            ResultKind::HealthGate,
        ] {
            record(&paths, &facts, Report::ok(kind, None)).unwrap();
        }
        let before = run_names(&paths);
        assert_eq!(before.len(), 3);
        reboot(&paths);
        assert!(run_names(&paths).is_empty());

        let first = mirror(&paths).unwrap();
        assert_eq!((first.restored, first.skipped.len()), (3, 0));
        assert_eq!(run_names(&paths), before);
        for name in &before {
            assert_eq!(
                std::fs::read(paths.run_results().join(name)).unwrap(),
                std::fs::read(paths.results_store().join(name)).unwrap(),
                "{name} is the bytes root wrote"
            );
            let mode = std::fs::metadata(paths.run_results().join(name))
                .unwrap()
                .permissions();
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
                0o640
            );
        }

        // Idempotent: nothing left to restore, and the next result continues the sequence.
        assert_eq!(mirror(&paths).unwrap().restored, 0);
        let next = record(&paths, &facts, Report::ok(ResultKind::VerifyCurrent, None)).unwrap();
        assert_eq!(next.seq, 4);
    }

    #[test]
    fn the_persistent_copy_replaces_a_mirror_that_differs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let doc = record(&paths, &facts, Report::ok(ResultKind::Lockdown, None)).unwrap();
        let name = format!("{:016}-lockdown.json", doc.seq);
        std::fs::write(paths.run_results().join(&name), b"{}").unwrap();
        assert_eq!(mirror(&paths).unwrap().restored, 1);
        assert_eq!(
            std::fs::read(paths.run_results().join(&name)).unwrap(),
            std::fs::read(paths.results_store().join(&name)).unwrap()
        );
    }

    #[test]
    fn without_data_there_is_nothing_to_restore_and_volatile_results_stay() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        std::fs::remove_dir(paths.os_state()).unwrap();
        record(
            &paths,
            &facts,
            Report::not_ok(
                ResultKind::DataUnlock,
                Outcome::Alarm,
                Reason::DataUnmountable,
            ),
        )
        .unwrap();
        let before = run_names(&paths);
        assert_eq!(before, ["volatile-0000000000000001-data-unlock.json"]);
        let report = mirror(&paths).unwrap();
        assert_eq!((report.restored, report.skipped.len()), (0, 0));
        assert_eq!(run_names(&paths), before);
        assert!(!paths.os_state().exists(), "nothing is created under /data");
    }

    #[test]
    fn a_store_with_no_results_yet_is_nothing_to_restore() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _facts) = image(tmp.path());
        let report = mirror(&paths).unwrap();
        assert_eq!((report.restored, report.skipped.len()), (0, 0));
        assert!(
            !paths.results_store().exists(),
            "restoring creates no store"
        );
    }

    /// The persistent store as a larger past left it: `count` valid results.
    fn store_of(paths: &Paths, facts: &ImageFacts, count: u64) {
        let template = record(paths, facts, Report::ok(ResultKind::VerifyCurrent, None)).unwrap();
        for seq in 2..=count {
            let mut doc = template.clone();
            doc.seq = seq;
            std::fs::write(
                paths
                    .results_store()
                    .join(format!("{seq:016}-verify-current.json")),
                serde_json::to_vec(&doc).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn only_the_newest_retained_results_are_restored() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let total = RETAINED as u64 + 4;
        store_of(&paths, &facts, total);
        reboot(&paths);
        assert_eq!(mirror(&paths).unwrap().restored, RETAINED);
        let kept = run_names(&paths);
        assert_eq!(kept.len(), RETAINED, "the newest {RETAINED}, no older one");
        assert_eq!(kept[0], "0000000000000005-verify-current.json");
        assert_eq!(
            kept[RETAINED - 1],
            format!("{total:016}-verify-current.json")
        );
    }

    #[test]
    fn results_older_than_the_retained_ones_leave_the_mirror() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let total = RETAINED as u64 + 4;
        store_of(&paths, &facts, total);
        // The mirror still holds the four oldest (a boot in which the store had
        // grown since: they are not retained any more).
        for seq in 1..=4 {
            std::fs::copy(
                paths
                    .results_store()
                    .join(format!("{seq:016}-verify-current.json")),
                paths
                    .run_results()
                    .join(format!("{seq:016}-verify-current.json")),
            )
            .unwrap();
        }
        mirror(&paths).unwrap();
        let kept = run_names(&paths);
        assert_eq!(kept.len(), RETAINED);
        assert_eq!(kept[0], "0000000000000005-verify-current.json");
    }

    #[test]
    fn a_result_file_that_is_not_a_result_is_skipped_and_named() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let good = record(&paths, &facts, Report::ok(ResultKind::Lockdown, None)).unwrap();
        let store = paths.results_store();
        // Garbage under a result's name, a document whose seq disagrees with its
        // name, and files that are not results at all.
        std::fs::write(store.join("0000000000000009-lockdown.json"), b"not json").unwrap();
        std::fs::copy(
            store.join(format!("{:016}-lockdown.json", good.seq)),
            store.join("0000000000000010-lockdown.json"),
        )
        .unwrap();
        std::fs::write(store.join("notes.txt"), b"x").unwrap();
        std::fs::write(store.join(".hidden.json"), b"x").unwrap();
        reboot(&paths);

        let report = mirror(&paths).unwrap();
        assert_eq!(report.restored, 1);
        assert_eq!(
            report.skipped,
            [
                "0000000000000009-lockdown.json",
                "0000000000000010-lockdown.json"
            ]
        );
        assert_eq!(run_names(&paths), ["0000000000000001-lockdown.json"]);
    }

    #[test]
    fn a_reason_outside_its_kind_is_never_written() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, facts) = image(tmp.path());
        let err = record(
            &paths,
            &facts,
            Report::not_ok(
                ResultKind::DataUnlock,
                Outcome::Alarm,
                Reason::SignatureInvalid,
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid result"));
        assert!(record(
            &paths,
            &facts,
            Report {
                kind: ResultKind::Lockdown,
                outcome: Outcome::Failed,
                reason: None,
                subject: None,
                detail: None,
            },
        )
        .is_err());
    }
}
