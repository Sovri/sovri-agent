// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 -- an incomplete corpus is not committed as a completed run. Covers
//! issue #343.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{ControlResult, Status};

const MIXED_RUN: &str = "mixed-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const GDPR_FRAMEWORK: &str = "gdpr-eprivacy";
const ISO_FRAMEWORK: &str = "iso-27001";
const ISO_VERSION: &str = "2022";
const ISO_URL: &str = "https://www.iso.org/standard/27001";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const CONSENT_TITLE: &str = "Prior consent for tracker access";
const CONSENT_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const SSH_CONTROL: &str = "host.ssh.permit-root-login";
const SSH_TITLE: &str = "Disallow SSH root login";
const SSH_REFERENCE: &str = "iso-27001:2022:A.8.2";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const SSH_RULE: &str = "host.ssh.detect-permit-root-login";
const PUBLIC_EVIDENCE_ID: &str = "ev-0001";
const SENSITIVE_EVIDENCE_ID: &str = "ev-0008";
const PUBLIC_EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SENSITIVE_EVIDENCE_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r03-incomplete-{}-{now}-{unique}",
            std::process::id()
        ));
        TempDatabase {
            db_path: root.join("tmp").join("sovri-mat-98.db"),
            root,
        }
    }

    fn path(&self) -> &Path {
        &self.db_path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn an_incomplete_corpus_is_not_committed_as_a_completed_run() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // Given corpus "mixed-2026-06-24" is missing framework metadata for "gdpr-eprivacy".
    let corpus = incomplete_mixed_corpus();

    // When the incomplete corpus is written to SQLite.
    let write_result = local_database.write_completed_corpus(&corpus);

    // Then the write is rejected.
    assert!(
        write_result.is_err(),
        "an incomplete corpus must not be accepted as a completed run"
    );

    // And run "mixed-2026-06-24" is not visible as a completed run.
    assert_row_absent(database.path(), "scan_runs", MIXED_RUN);

    // And no framework row for "gdpr-eprivacy" is committed for run "mixed-2026-06-24".
    assert_row_absent(database.path(), "frameworks", GDPR_FRAMEWORK);

    // And no control row for "consent.tracker.prior-consent" is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), "controls");

    // And no result row for "consent.detect-trackers-without-consent-evidence" is committed.
    assert_table_empty(database.path(), "control_results");

    // And no partial compliance gap for "consent.tracker.prior-consent" is committed.
    assert_table_empty(database.path(), "compliance_gaps");

    // And no evidence metadata row for "ev-0001" is committed for run "mixed-2026-06-24".
    assert_row_absent(database.path(), "evidence_metadata", PUBLIC_EVIDENCE_ID);

    // And no score summary is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), "score_summaries");

    // And no export record is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), "exports");
}

fn incomplete_mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN)
        .with_framework(ISO_FRAMEWORK, ISO_VERSION, ISO_URL)
        .with_control(
            GDPR_FRAMEWORK,
            CONSENT_CONTROL,
            CONSENT_TITLE,
            "major",
            8,
            CONSENT_REFERENCE,
        )
        .with_control(
            ISO_FRAMEWORK,
            SSH_CONTROL,
            SSH_TITLE,
            "minor",
            8,
            SSH_REFERENCE,
        )
        .with_control_result(
            GDPR_FRAMEWORK,
            control_result(
                CONSENT_CONTROL,
                TRACKER_RULE,
                "major",
                Status::Fail,
                PUBLIC_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            GDPR_FRAMEWORK,
            control_result(
                CONSENT_CONTROL,
                CMP_RULE,
                "major",
                Status::Pass,
                PUBLIC_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            ISO_FRAMEWORK,
            control_result(
                SSH_CONTROL,
                SSH_RULE,
                "minor",
                Status::Warning,
                SENSITIVE_EVIDENCE_ID,
            ),
        )
        .with_evidence_digest(
            PUBLIC_EVIDENCE_ID,
            "file",
            "dist/main.js",
            PUBLIC_EVIDENCE_DIGEST,
        )
        .with_classified_evidence(
            SENSITIVE_EVIDENCE_ID,
            "config",
            "config/users.yaml:12",
            Classification::Sensitive,
            SENSITIVE_EVIDENCE_DIGEST,
        )
}

fn control_result(
    control_id: &str,
    rule_id: &str,
    severity: &str,
    status: Status,
    evidence_id: &str,
) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity(severity)
        .weight(8)
        .evidence_refs([evidence_id])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the mixed compliance run.");
    }
    builder.build().expect("the mixed fixture result validates")
}

fn assert_row_absent(path: &Path, table_name: &str, id: &str) {
    assert_eq!(
        row_count(path, table_name, id),
        0,
        "{table_name} should not contain row {id:?}"
    );
}

fn assert_table_empty(path: &Path, table_name: &str) {
    assert_eq!(
        table_row_count(path, table_name),
        0,
        "{table_name} should remain empty after the rejected write"
    );
}

fn row_count(path: &Path, table_name: &str, id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    let sql = format!("SELECT COUNT(*) FROM {table_name} WHERE id = ?1");
    connection
        .query_row(&sql, [id], |row| row.get(0))
        .expect("row count can be inspected")
}

fn table_row_count(path: &Path, table_name: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    let sql = format!("SELECT COUNT(*) FROM {table_name}");
    connection
        .query_row(&sql, [], |row| row.get(0))
        .expect("table row count can be inspected")
}
