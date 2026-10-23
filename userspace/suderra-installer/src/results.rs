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
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(crate::fsutil::libc_flags::O_NOFOLLOW)
        .open(counter_dir.join(".lock"))
        .context("cannot open the results lock")?;
    let _lock = Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, errno)| anyhow::anyhow!("cannot lock results: {errno}"))?;

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

    let run = paths.run_results();
    ensure_dir(&paths.run_suderra(), 0o750)?;
    ensure_dir(&run, 0o750)?;
    if let Some(gid) = paths.agent_group() {
        std::os::unix::fs::chown(paths.run_suderra(), None, Some(gid.as_raw()))
            .context("cannot chgrp /run/suderra")?;
        std::os::unix::fs::chown(&run, None, Some(gid.as_raw()))
            .context("cannot chgrp /run/suderra/results")?;
    }
    write_atomic(&run.join(&name), &bytes, 0o640, paths.agent_group())?;
    prune(&run)?;
    Ok(doc)
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
