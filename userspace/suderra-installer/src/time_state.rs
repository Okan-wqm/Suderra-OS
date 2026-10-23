// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock trust, as root's time helper publishes it (ADR-048 DEC-7.3, DEC-7.5;
//! contracts schemas/time-state.schema.json and channels.json `time`).
//!
//! `suderra-time-state` rewrites `/run/suderra/time-state` every 15 s from
//! chronyd's reports and the time floor. The document is a claim of its
//! writer's last write, so a reader never takes it at its word alone: an
//! absent, unreadable or non-conforming document, and one whose `updated_at` is
//! more than `MAX_AGE_SECONDS` from the reader's own clock in either direction,
//! is `unsynced` (channels.json `time.stale_rule`). A writer that stopped, and a
//! clock that moved since the last write, cannot be told from a document that is
//! still true, and `unsynced` is the answer that holds nothing back that should
//! have been refused. The agent's reader (`runtime_safety/time_state_clock.rs` of
//! aquaculture_platform) applies the same rule; the document is parsed as
//! strictly as every document of the contract.
//!
//! The installer records the state in every result it writes
//! (`result.schema.json` `time_state`).

use crate::contracts::encoding::is_timestamp;
use crate::contracts::json::{check_strict_object, MAX_SAFE_INTEGER};
use crate::contracts::registry::TimeState;
use crate::fsutil::read_root_file;
use crate::paths::Paths;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// `_type` of the document.
pub(crate) const DOCUMENT_TYPE: &str = "suderra.time-state.v1";

/// channels.json `time.max_age_seconds`: how far `updated_at` may be from the
/// reader's clock, in either direction.
pub(crate) const MAX_AGE_SECONDS: i64 = 120;

/// The document's name under /run/suderra (channels.json `time.document`).
pub(crate) const FILE_NAME: &str = "time-state";

/// A document is a few hundred bytes; anything near this is not one.
const MAX_DOCUMENT_BYTES: u64 = 4096;

/// The members of the document, all required (the schema's `required` list;
/// `additionalProperties` is false).
const MEMBERS: [&str; 6] = [
    "_type",
    "state",
    "floor_at",
    "last_sync_at",
    "offset_ms",
    "updated_at",
];

/// The clock trust right now, as of `now`: the document's state when it
/// conforms and is fresh, `Unsynced` for everything else.
pub(crate) fn read(paths: &Paths, now: DateTime<Utc>) -> TimeState {
    read_root_file(&paths.run_suderra().join(FILE_NAME), MAX_DOCUMENT_BYTES)
        .ok()
        .flatten()
        .and_then(|bytes| parse(&bytes, now).ok())
        .unwrap_or(TimeState::Unsynced)
}

/// The state of a document read at `now`, or the reason it counts as unsynced.
pub(crate) fn parse(bytes: &[u8], now: DateTime<Utc>) -> Result<TimeState, String> {
    check_strict_object(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("not an object")?;
    if object.len() != MEMBERS.len() || MEMBERS.iter().any(|m| !object.contains_key(*m)) {
        return Err(format!("the members are not exactly {MEMBERS:?}"));
    }
    if object["_type"].as_str() != Some(DOCUMENT_TYPE) {
        return Err(format!("_type is not {DOCUMENT_TYPE}"));
    }
    let state = object["state"]
        .as_str()
        .and_then(TimeState::parse)
        .ok_or("state is not a time state")?;
    let timestamp = |member: &str| -> Result<String, String> {
        object[member]
            .as_str()
            .filter(|text| is_timestamp(text))
            .map(str::to_owned)
            .ok_or_else(|| format!("{member} is not a timestamp"))
    };
    timestamp("floor_at")?;
    let updated_at = timestamp("updated_at")?;
    let last_sync = &object["last_sync_at"];
    if !last_sync.is_null() {
        timestamp("last_sync_at")?;
    }
    let offset = &object["offset_ms"];
    if !offset.is_null() {
        let magnitude = offset
            .as_i64()
            .map(i64::unsigned_abs)
            .ok_or("offset_ms is not an integer")?;
        if magnitude > MAX_SAFE_INTEGER {
            return Err("offset_ms is beyond 2^53-1".into());
        }
    }
    // The schema's allOf: unsynced has no offset, a synchronized clock has an
    // offset and the time of its last synchronization.
    match state {
        TimeState::Unsynced => {
            if !offset.is_null() {
                return Err("an unsynced clock has no offset_ms".into());
            }
        }
        TimeState::SyncedNts | TimeState::SyncedUnauthenticated => {
            if offset.is_null() || last_sync.is_null() {
                return Err("a synchronized clock has offset_ms and last_sync_at".into());
            }
        }
    }
    let written = DateTime::parse_from_rfc3339(&updated_at)
        .map_err(|e| format!("updated_at: {e}"))?
        .with_timezone(&Utc);
    let age = now.signed_duration_since(written).num_seconds();
    if age.abs() > MAX_AGE_SECONDS {
        return Err(format!(
            "updated_at is {age} s from this clock, more than {MAX_AGE_SECONDS}"
        ));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::image;
    use chrono::TimeZone;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 23, 0, 16, second).unwrap()
    }

    /// What suderra-time-state wrote against a loopback NTS server of chrony
    /// 4.6.1 (tests/image-contracts/time-state-helper-test.sh), read at the
    /// instant it was written.
    const NTS: &str = r#"{"_type":"suderra.time-state.v1","state":"synced-nts","floor_at":"2025-10-09T08:53:20Z","last_sync_at":"2026-10-23T00:15:55Z","offset_ms":0,"updated_at":"2026-10-23T00:16:40Z"}"#;

    fn document(state: &str, last_sync: &str, offset: &str, updated: &str) -> String {
        format!(
            r#"{{"_type":"suderra.time-state.v1","state":"{state}","floor_at":"2025-10-09T08:53:20Z","last_sync_at":{last_sync},"offset_ms":{offset},"updated_at":"{updated}"}}"#
        )
    }

    #[test]
    fn the_document_the_helper_writes_reads_back() {
        assert_eq!(parse(NTS.as_bytes(), at(40)), Ok(TimeState::SyncedNts));
        let unauthenticated = document(
            "synced-unauthenticated",
            r#""2026-10-23T00:15:55Z""#,
            "-12",
            "2026-10-23T00:16:40Z",
        );
        assert_eq!(
            parse(unauthenticated.as_bytes(), at(40)),
            Ok(TimeState::SyncedUnauthenticated)
        );
        let unsynced = document("unsynced", "null", "null", "2026-10-23T00:16:40Z");
        assert_eq!(parse(unsynced.as_bytes(), at(40)), Ok(TimeState::Unsynced));
        // An unsynchronized clock that did synchronize earlier keeps the time.
        let lapsed = document(
            "unsynced",
            r#""2026-10-23T00:15:55Z""#,
            "null",
            "2026-10-23T00:16:40Z",
        );
        assert_eq!(parse(lapsed.as_bytes(), at(40)), Ok(TimeState::Unsynced));
    }

    #[test]
    fn a_document_older_than_two_minutes_is_unsynced_in_either_direction() {
        let written = "2026-10-23T00:16:40Z"; // at(40)
        let doc = document("synced-nts", r#""2026-10-23T00:15:55Z""#, "0", written);
        // Exactly 120 s away is still fresh; 121 s is not.
        assert_eq!(
            parse(
                doc.as_bytes(),
                Utc.with_ymd_and_hms(2026, 10, 23, 0, 18, 40).unwrap()
            ),
            Ok(TimeState::SyncedNts)
        );
        assert!(parse(
            doc.as_bytes(),
            Utc.with_ymd_and_hms(2026, 10, 23, 0, 18, 41).unwrap()
        )
        .unwrap_err()
        .contains("updated_at is 121 s"));
        // A reader whose clock is behind the writer's (it was set back, or the
        // writer's was set forward) refuses the same way.
        assert_eq!(
            parse(
                doc.as_bytes(),
                Utc.with_ymd_and_hms(2026, 10, 23, 0, 14, 40).unwrap()
            ),
            Ok(TimeState::SyncedNts)
        );
        assert!(parse(
            doc.as_bytes(),
            Utc.with_ymd_and_hms(2026, 10, 23, 0, 14, 39).unwrap()
        )
        .unwrap_err()
        .contains("updated_at is -121 s"));
    }

    #[test]
    fn a_document_that_breaks_the_schema_is_refused() {
        let fresh = "2026-10-23T00:16:40Z";
        let sync = r#""2026-10-23T00:15:55Z""#;
        let cases: Vec<(&str, String)> = vec![
            ("not JSON", "synced-nts\n".into()),
            ("the old plain-text state", "unsynced".into()),
            ("an array", "[]".into()),
            (
                "an unknown member",
                NTS.replace("\"offset_ms\":0,", "\"offset_ms\":0,\"extra\":1,"),
            ),
            ("a missing member", NTS.replace("\"offset_ms\":0,", "")),
            (
                "a duplicate member",
                NTS.replace("\"offset_ms\":0,", "\"offset_ms\":0,\"offset_ms\":1,"),
            ),
            (
                "a wrong _type",
                NTS.replace("time-state.v1", "time-state.v2"),
            ),
            ("an unknown state", NTS.replace("synced-nts", "synced")),
            (
                "a fractional offset",
                document("synced-nts", sync, "0.5", fresh),
            ),
            (
                "a string offset",
                document("synced-nts", sync, "\"0\"", fresh),
            ),
            (
                "an offset beyond 2^53-1",
                document("synced-nts", sync, "9007199254740992", fresh),
            ),
            (
                "a timestamp with a fraction",
                document("synced-nts", sync, "0", "2026-10-23T00:16:40.5Z"),
            ),
            (
                "a timestamp with an offset",
                document("synced-nts", sync, "0", "2026-10-23T00:16:40+00:00"),
            ),
            (
                "a null updated_at",
                NTS.replace("\"2026-10-23T00:16:40Z\"}", "null}"),
            ),
            (
                "a synchronized clock without an offset",
                document("synced-nts", sync, "null", fresh),
            ),
            (
                "a synchronized clock without a sync time",
                document("synced-nts", "null", "0", fresh),
            ),
            (
                "an unsynced clock with an offset",
                document("unsynced", "null", "0", fresh),
            ),
            ("a byte order mark", format!("\u{feff}{NTS}")),
            ("trailing data", format!("{NTS}\n{{}}")),
        ];
        for (name, text) in cases {
            assert!(
                parse(text.as_bytes(), at(40)).is_err(),
                "{name} must be refused: {text}"
            );
        }
    }

    #[test]
    fn the_state_comes_from_the_file_and_everything_else_is_unsynced() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (paths, _facts) = image(tmp.path());
        let run = paths.run_suderra();
        std::fs::create_dir_all(&run).unwrap();
        let file = run.join(FILE_NAME);
        let now = at(40);

        assert_eq!(read(&paths, now), TimeState::Unsynced, "absent");
        std::fs::write(&file, NTS).unwrap();
        assert_eq!(read(&paths, now), TimeState::SyncedNts);
        std::fs::write(&file, "x".repeat(5000)).unwrap();
        assert_eq!(read(&paths, now), TimeState::Unsynced, "oversize");
        std::fs::write(&file, "unsynced").unwrap();
        assert_eq!(read(&paths, now), TimeState::Unsynced, "non-conforming");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert_eq!(read(&paths, now), TimeState::Unsynced, "a directory");
        std::fs::remove_dir(&file).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, NTS).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        assert_eq!(
            read(&paths, now),
            TimeState::Unsynced,
            "a symlink is not followed"
        );
    }

    #[test]
    fn the_constants_are_the_contracts() {
        let contract = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/suderra-edge/v1");
        let channels: Value =
            serde_json::from_slice(&std::fs::read(contract.join("channels.json")).unwrap())
                .unwrap();
        let time = &channels["time"];
        assert_eq!(time["max_age_seconds"], MAX_AGE_SECONDS);
        assert_eq!(
            time["document"].as_str().unwrap(),
            format!("/run/suderra/{FILE_NAME}")
        );
        let schema: Value = serde_json::from_slice(
            &std::fs::read(contract.join("schemas/time-state.schema.json")).unwrap(),
        )
        .unwrap();
        let mut required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect();
        required.sort_unstable();
        let mut ours = MEMBERS.to_vec();
        ours.sort_unstable();
        assert_eq!(required, ours);
        assert_eq!(schema["properties"]["_type"]["const"], DOCUMENT_TYPE);
        // Every state the contract names is one the registry knows.
        let states: Vec<&str> = schema["properties"]["state"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(
            states,
            TimeState::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
        );
    }
}
