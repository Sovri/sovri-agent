// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 -- repeated writes cannot duplicate gaps or scores. Covers issue #347.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const CONTROL_ID: &str = "consent.tracker.prior-consent";
const CONTROL_TITLE: &str = "Prior consent for tracker access";
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const EVIDENCE_ID: &str = "ev-0001";
const EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

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
            "sovri-agent-mat98-r04-no-duplicate-gaps-scores-{}-{now}-{unique}",
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
fn a_repeated_write_cannot_duplicate_gaps_or_scores() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // When the "shopfront-2026-06-24" corpus is written to SQLite.
    local_database
        .write_completed_corpus(&consent_corpus())
        .expect("the initial corpus write succeeds");

    // And the "shopfront-2026-06-24" corpus is written to SQLite again.
    local_database
        .write_completed_corpus(&consent_corpus())
        .expect("the repeated corpus write succeeds");

    // Then exactly 1 gap row exists for rule "consent.detect-trackers-without-consent-evidence".
    assert_eq!(gap_row_count(database.path(), TRACKER_RULE), 1);

    // And exactly 1 score summary exists for framework "gdpr-eprivacy".
    assert_eq!(
        score_summary_count(database.path(), RUN_ID, FRAMEWORK_ID),
        1
    );

    // And no duplicate logical record is returned by run, evidence, result, gap, or score queries.
    assert_no_duplicate_logical_records(database.path());
}

fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK_ID,
            CONTROL_ID,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK_ID, control_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK_ID, control_result(CMP_RULE, Status::Pass))
        .with_evidence_digest(
            EVIDENCE_ID,
            "file",
            "shopfront/dist/main.js",
            EVIDENCE_DIGEST,
        )
}

fn control_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL_ID)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the shopfront consent run.");
    }
    builder
        .build()
        .expect("the shopfront consent result validates")
}

fn gap_row_count(path: &Path, rule_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM compliance_gaps WHERE id LIKE ?1",
            params![format!("%:{rule_id}")],
            |row| row.get(0),
        )
        .expect("gap row count can be inspected")
}

fn score_summary_count(path: &Path, run_id: &str, framework_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*)
             FROM score_summaries
             WHERE run_id = ?1 AND framework_id = ?2",
            params![run_id, framework_id],
            |row| row.get(0),
        )
        .expect("score summary count can be inspected")
}

fn assert_no_duplicate_logical_records(path: &Path) {
    let connection = Connection::open(path).expect("the database can be inspected");
    for table in [
        "scan_runs",
        "evidence_metadata",
        "control_results",
        "compliance_gaps",
        "score_summaries",
    ] {
        let ids = logical_record_ids(&connection, table);
        let unique_ids = ids.iter().collect::<BTreeSet<_>>();
        assert_eq!(
            ids.len(),
            unique_ids.len(),
            "{table} query returns no duplicate logical records"
        );
    }
}

fn logical_record_ids(connection: &Connection, table: &str) -> Vec<String> {
    let sql = format!("SELECT id FROM {table} ORDER BY id");
    let mut statement = connection
        .prepare(&sql)
        .expect("logical record query can be prepared");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("logical record query can run");
    rows.collect::<Result<Vec<_>, _>>()
        .expect("logical record ids can be read")
}
