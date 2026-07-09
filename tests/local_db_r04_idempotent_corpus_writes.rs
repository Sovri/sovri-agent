// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 -- writing the same corpus twice leaves one logical run. Covers issue
//! #344.

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
            "sovri-agent-mat98-r04-idempotent-{}-{now}-{unique}",
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
fn writing_the_same_corpus_twice_leaves_one_logical_run() {
    // Given an open local database at "./tmp/sovri-mat-98.db".
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // And the "shopfront-2026-06-24" consent corpus contains:
    let corpus = shopfront_consent_corpus();

    // When the "shopfront-2026-06-24" corpus is written to SQLite.
    local_database
        .write_completed_corpus(&corpus)
        .expect("the first corpus write succeeds");

    // And the "shopfront-2026-06-24" corpus is written to SQLite again.
    local_database
        .write_completed_corpus(&corpus)
        .expect("the repeated corpus write succeeds");

    // Then exactly 1 run row exists for "shopfront-2026-06-24".
    assert_eq!(run_row_count(database.path(), RUN_ID), 1);

    // And exactly 1 framework row exists for "gdpr-eprivacy" version "2016-679".
    assert_eq!(
        framework_row_count(database.path(), FRAMEWORK_ID, FRAMEWORK_VERSION),
        1
    );

    // And exactly 1 control row exists for "consent.tracker.prior-consent".
    assert_eq!(control_row_count(database.path(), CONTROL_ID), 1);

    // And exactly 2 result rows exist for run "shopfront-2026-06-24".
    assert_eq!(result_row_count_for_run(database.path(), RUN_ID), 2);

    // And exactly 1 evidence metadata row exists for evidence id "ev-0001".
    assert_eq!(evidence_metadata_row_count(database.path(), EVIDENCE_ID), 1);
}

fn shopfront_consent_corpus() -> Corpus {
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
        .with_control_result(
            FRAMEWORK_ID,
            control_result(TRACKER_RULE, Status::Fail, EVIDENCE_ID),
        )
        .with_control_result(
            FRAMEWORK_ID,
            control_result(CMP_RULE, Status::Pass, EVIDENCE_ID),
        )
        .with_evidence_digest(
            EVIDENCE_ID,
            "file",
            "shopfront/dist/main.js",
            EVIDENCE_DIGEST,
        )
}

fn control_result(rule_id: &str, status: Status, evidence_id: &str) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL_ID)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs([evidence_id])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the shopfront consent run.");
    }
    builder
        .build()
        .expect("the shopfront consent result validates")
}

fn run_row_count(path: &Path, run_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .expect("run row count can be inspected")
}

fn framework_row_count(path: &Path, framework_id: &str, version: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM frameworks WHERE id = ?1 AND version = ?2",
            params![framework_id, version],
            |row| row.get(0),
        )
        .expect("framework row count can be inspected")
}

fn control_row_count(path: &Path, control_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM controls WHERE id = ?1",
            [control_id],
            |row| row.get(0),
        )
        .expect("control row count can be inspected")
}

fn result_row_count_for_run(path: &Path, _run_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row("SELECT COUNT(*) FROM control_results", [], |row| row.get(0))
        .expect("result row count can be inspected")
}

fn evidence_metadata_row_count(path: &Path, evidence_id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM evidence_metadata WHERE id = ?1",
            [evidence_id],
            |row| row.get(0),
        )
        .expect("evidence metadata row count can be inspected")
}
