// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! `suderra-installer result write`: typed results for the root helper
//! scripts (suderra-lockdown, suderra-data-unlock, suderra-time-state),
//! validated against the result schema like every other result (DEC-27).

use crate::cli::{ResultArgs, ResultCommand};
use crate::contracts::registry::{Outcome, Reason, ResultKind};
use crate::paths::Paths;
use crate::results::{record, Report};
use crate::variant::ImageFacts;
use anyhow::{Context, Result};

/// Builds a report from command-line text.
pub(crate) fn report_from_args(
    kind: &str,
    outcome: &str,
    reason: Option<&str>,
    detail: Option<&str>,
) -> Result<Report> {
    let kind = ResultKind::parse(kind).with_context(|| format!("unknown result kind {kind:?}"))?;
    let outcome =
        Outcome::parse(outcome).with_context(|| format!("unknown outcome {outcome:?}"))?;
    let reason = reason
        .map(|r| Reason::parse(r).with_context(|| format!("unknown reason {r:?}")))
        .transpose()?;
    let report = Report {
        kind,
        outcome,
        reason,
        subject: None,
        detail: None,
    };
    Ok(match detail {
        Some(d) => report.with_detail(d),
        None => report,
    })
}

/// `suderra-installer result <command>`.
pub(crate) fn run(args: ResultArgs) -> Result<()> {
    match args.command {
        ResultCommand::Write(w) => {
            let report = report_from_args(
                &w.kind,
                &w.outcome,
                w.reason.as_deref(),
                w.detail.as_deref(),
            )?;
            let paths = Paths::system()?;
            let facts = ImageFacts::load(&paths)?;
            let doc = record(&paths, &facts, report)?;
            println!("{}", doc.seq);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_reports_are_typed() {
        assert!(report_from_args("lockdown", "failed", Some("firewall-load-failed"), None).is_ok());
        assert!(report_from_args("lockdown", "exploded", Some("io-error"), None).is_err());
        assert!(report_from_args("lockdown", "failed", Some("no-such-reason"), None).is_err());
        assert!(report_from_args("installation", "ok", None, None).is_err());
    }
}
