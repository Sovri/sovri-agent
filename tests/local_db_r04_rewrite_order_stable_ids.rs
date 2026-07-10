// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 -- rewriting in a different input order preserves stable ids. Covers
//! issue #345.

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
const TRACKER_RESULT_ID: &str =
    "consent.tracker.prior-consent/consent.detect-trackers-without-consent-evidence";
const CMP_RESULT_ID: &str = "consent.tracker.prior-consent/consent.detect-cmp-misconfiguration";
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
            "sovri-agent-mat98-r04-rewrite-order-{}-{now}-{unique}",
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
fn rewriting_in_a_different_input_order_preserves_stable_ids() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // Given the "shopfront-2026-06-24" corpus has already been written to SQLite.
    local_database
        .write_completed_corpus(&consent_corpus_fail_then_pass())
        .expect("the initial corpus write succeeds");

    // When the same corpus is written again with the PASS result before the FAIL result.
    local_database
        .write_completed_corpus(&consent_corpus_pass_then_fail())
        .expect("the reordered corpus write succeeds");

    // Then result "consent.tracker.prior-consent/consent.detect-trackers-without-consent-evidence" still references evidence "ev-0001".
    assert_eq!(
        result_evidence_id(database.path(), TRACKER_RESULT_ID),
        EVIDENCE_ID
    );

    // And result "consent.tracker.prior-consent/consent.detect-cmp-misconfiguration" still references evidence "ev-0001".
    assert_eq!(
        result_evidence_id(database.path(), CMP_RESULT_ID),
        EVIDENCE_ID
    );

    // And evidence digest "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" is stored once.
    assert_eq!(
        evidence_digest_row_count(database.path(), EVIDENCE_DIGEST),
        1
    );
}

fn consent_corpus_fail_then_pass() -> Corpus {
    consent_corpus([
        control_result(TRACKER_RULE, Status::Fail),
        control_result(CMP_RULE, Status::Pass),
    ])
}

fn consent_corpus_pass_then_fail() -> Corpus {
    consent_corpus([
        control_result(CMP_RULE, Status::Pass),
        control_result(TRACKER_RULE, Status::Fail),
    ])
}

fn consent_corpus(results: [ControlResult; 2]) -> Corpus {
    let mut corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK_ID,
            CONTROL_ID,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        );
    for result in results {
        corpus = corpus.with_control_result(FRAMEWORK_ID, result);
    }
    corpus.with_evidence_digest(
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

fn result_evidence_id(path: &Path, result_id: &str) -> String {
    let (control_id, rule_id) = result_id
        .split_once('/')
        .expect("scenario result id is control/rule");
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT evidence_id FROM control_results WHERE control_id = ?1 AND rule_id = ?2",
            params![control_id, rule_id],
            |row| row.get(0),
        )
        .expect("result evidence id can be inspected")
}

fn evidence_digest_row_count(path: &Path, digest: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(
            "SELECT COUNT(*) FROM evidence_metadata WHERE digest = ?1",
            params![digest],
            |row| row.get(0),
        )
        .expect("evidence digest row count can be inspected")
}
