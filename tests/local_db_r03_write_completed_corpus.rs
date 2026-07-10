// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 -- writing a completed corpus persists every required section. Covers
//! issue #341.

mod matrix_support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use matrix_support::{
    consent_corpus, CONTROL, CONTROL_REFERENCE, CONTROL_TITLE, EXECUTED_AT, FRAMEWORK,
    FRAMEWORK_URL, FRAMEWORK_VERSION, STORED_EVIDENCE_ID, STORED_EVIDENCE_INTEGRITY,
    STORED_EVIDENCE_KIND, STORED_EVIDENCE_LOCATION,
};
use rusqlite::Connection;
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{ControlResult, Status};

const SHOPFRONT_RUN: &str = "shopfront-2026-06-24";
const SHOPFRONT_REPLAY_RUN: &str = "shopfront-replay-2026-06-24";
const CONCURRENT_RUN: &str = "shopfront-concurrent-2026-06-24";
const MIXED_RUN: &str = "mixed-2026-06-24";
const CLASSIFIED_EVIDENCE_RUN: &str = "classified-evidence-2026-06-24";
const STORED_RECORD_RUN: &str = "stored-record-2026-06-24";

const ISO_27001_FRAMEWORK: &str = "iso-27001";
const ISO_27001_VERSION: &str = "2022";
const ISO_27001_URL: &str = "https://www.iso.org/standard/27001";
const SSH_CONTROL: &str = "host.ssh.permit-root-login";
const SSH_CONTROL_TITLE: &str = "Disallow SSH root login";
const SSH_CONTROL_REFERENCE: &str = "iso-27001:2022:A.8.2";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const SSH_RULE: &str = "host.ssh.detect-permit-root-login";
const PUBLIC_EVIDENCE_ID: &str = "ev-0001";
const SENSITIVE_EVIDENCE_ID: &str = "ev-0008";
const PUBLIC_EVIDENCE_LOCATOR: &str = "dist/main.js";
const SENSITIVE_EVIDENCE_LOCATOR: &str = "config/users.yaml:12";
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
            "sovri-agent-mat98-r03-{}-{now}-{unique}",
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

struct CompletedCorpusCase {
    run: &'static str,
    corpus: Corpus,
    framework_count: usize,
    control_count: usize,
    result_count: usize,
    gap_count: usize,
    evidence_count: usize,
    score_count: usize,
}

#[test]
fn writing_a_completed_corpus_persists_every_required_section() {
    for case in completed_corpus_examples() {
        let database = TempDatabase::new();
        // Given an open local database at "./tmp/sovri-mat-98.db".
        let mut local_database =
            LocalDatabase::open(database.path()).expect("the local database opens");

        // Given completed scan corpus "<run>" is available locally.
        let corpus = case.corpus;

        // When the completed corpus "<run>" is written to SQLite.
        local_database
            .write_completed_corpus(&corpus)
            .expect("the completed corpus is written to SQLite");

        // Then run "<run>" can be retrieved with executed-at "2026-06-24T13:16:28Z".
        assert_eq!(
            local_database
                .completed_run_executed_at(case.run)
                .expect("the completed run can be retrieved")
                .as_deref(),
            Some(EXECUTED_AT),
            "run {:?} should be retrievable with executed-at {:?}",
            case.run,
            EXECUTED_AT
        );

        // And <framework_count> framework records can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .framework_records_for_run(case.run)
                .expect("framework records can be retrieved")
                .len(),
            case.framework_count,
            "framework record count for {:?}",
            case.run
        );

        // And <control_count> control records can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .control_records_for_run(case.run)
                .expect("control records can be retrieved")
                .len(),
            case.control_count,
            "control record count for {:?}",
            case.run
        );

        // And <result_count> control results can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .control_result_records_for_run(case.run)
                .expect("control results can be retrieved")
                .len(),
            case.result_count,
            "control result count for {:?}",
            case.run
        );

        // And <gap_count> compliance gaps can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .compliance_gap_records_for_run(case.run)
                .expect("compliance gaps can be retrieved")
                .len(),
            case.gap_count,
            "compliance gap count for {:?}",
            case.run
        );

        // And <evidence_count> evidence metadata records can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .evidence_metadata_records_for_run(case.run)
                .expect("evidence metadata records can be retrieved")
                .len(),
            case.evidence_count,
            "evidence metadata count for {:?}",
            case.run
        );

        // And <score_count> score summaries can be retrieved for run "<run>".
        assert_eq!(
            local_database
                .score_summary_records_for_run(case.run)
                .expect("score summaries can be retrieved")
                .len(),
            case.score_count,
            "score summary count for {:?}",
            case.run
        );
    }
}

#[test]
fn query_helpers_return_empty_results_for_unknown_runs() {
    let database = TempDatabase::new();
    let local_database = LocalDatabase::open(database.path()).expect("the local database opens");

    for run_id in ["missing-run", "", "' OR 1 = 1 --"] {
        assert_eq!(
            local_database
                .completed_run_executed_at(run_id)
                .expect("an unknown run can be queried"),
            None,
            "executed-at should be absent for {run_id:?}"
        );

        for (section, records) in [
            (
                "frameworks",
                local_database.framework_records_for_run(run_id),
            ),
            ("controls", local_database.control_records_for_run(run_id)),
            (
                "control results",
                local_database.control_result_records_for_run(run_id),
            ),
            (
                "compliance gaps",
                local_database.compliance_gap_records_for_run(run_id),
            ),
            (
                "evidence metadata",
                local_database.evidence_metadata_records_for_run(run_id),
            ),
            (
                "score summaries",
                local_database.score_summary_records_for_run(run_id),
            ),
        ] {
            assert!(
                records
                    .unwrap_or_else(|error| panic!(
                        "{section} query failed for {run_id:?}: {error}"
                    ))
                    .is_empty(),
                "{section} should be empty for {run_id:?}"
            );
        }
    }
}

#[test]
fn writing_a_completed_corpus_upgrades_legacy_section_tables() {
    let database = TempDatabase::new();
    create_legacy_completed_corpus_schema(database.path());
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the legacy local database opens");

    local_database
        .write_completed_corpus(&consent_corpus().with_run_id(SHOPFRONT_RUN))
        .expect("the completed corpus is written to legacy section tables");

    assert_eq!(
        local_database
            .completed_run_executed_at(SHOPFRONT_RUN)
            .expect("the completed run can be retrieved")
            .as_deref(),
        Some(EXECUTED_AT)
    );
    assert_eq!(
        local_database
            .framework_records_for_run(SHOPFRONT_RUN)
            .expect("framework records can be retrieved")
            .len(),
        1
    );
    assert_eq!(
        local_database
            .control_records_for_run(SHOPFRONT_RUN)
            .expect("control records can be retrieved")
            .len(),
        1
    );
    assert_eq!(
        local_database
            .control_result_records_for_run(SHOPFRONT_RUN)
            .expect("control results can be retrieved")
            .len(),
        2
    );
    assert_eq!(
        local_database
            .compliance_gap_records_for_run(SHOPFRONT_RUN)
            .expect("compliance gaps can be retrieved")
            .len(),
        1
    );
    assert_eq!(
        local_database
            .evidence_metadata_records_for_run(SHOPFRONT_RUN)
            .expect("evidence metadata records can be retrieved")
            .len(),
        1
    );
    assert_eq!(
        local_database
            .score_summary_records_for_run(SHOPFRONT_RUN)
            .expect("score summaries can be retrieved")
            .len(),
        1
    );

    local_database
        .write_completed_corpus(&consent_corpus().with_run_id(SHOPFRONT_REPLAY_RUN))
        .expect("a second run with overlapping ids is written to upgraded section tables");

    assert_eq!(
        local_database
            .framework_records_for_run(SHOPFRONT_RUN)
            .expect("the first run's framework records can still be retrieved")
            .len(),
        1
    );
    assert_eq!(
        local_database
            .framework_records_for_run(SHOPFRONT_REPLAY_RUN)
            .expect("the second run's framework records can be retrieved")
            .len(),
        1
    );
    assert_shared_evidence_keeps_both_run_links(database.path());
    assert_legacy_rows_are_preserved(database.path());
}

#[test]
fn writing_a_completed_corpus_replaces_existing_run_sections() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    local_database
        .write_completed_corpus(&mixed_completed_corpus().with_run_id(MIXED_RUN))
        .expect("the original completed corpus is written to SQLite");
    assert_eq!(
        local_database
            .framework_records_for_run(MIXED_RUN)
            .expect("original framework records can be retrieved")
            .len(),
        2
    );
    assert_eq!(
        local_database
            .evidence_metadata_records_for_run(MIXED_RUN)
            .expect("original evidence metadata can be retrieved")
            .len(),
        2
    );

    local_database
        .write_completed_corpus(&consent_corpus().with_run_id(MIXED_RUN))
        .expect("the corrected completed corpus is written to SQLite");

    assert_eq!(
        local_database
            .framework_records_for_run(MIXED_RUN)
            .expect("replacement framework records can be retrieved"),
        vec![FRAMEWORK.to_owned()]
    );
    assert_eq!(
        local_database
            .control_records_for_run(MIXED_RUN)
            .expect("replacement control records can be retrieved"),
        vec![CONTROL.to_owned()]
    );
    assert_eq!(
        local_database
            .control_result_records_for_run(MIXED_RUN)
            .expect("replacement control results can be retrieved"),
        vec![
            format!("{FRAMEWORK}:{CONTROL}:{CMP_RULE}"),
            format!("{FRAMEWORK}:{CONTROL}:{TRACKER_RULE}"),
        ]
    );
    assert_eq!(
        local_database
            .compliance_gap_records_for_run(MIXED_RUN)
            .expect("replacement compliance gaps can be retrieved"),
        vec![format!("{FRAMEWORK}:{CONTROL}:{TRACKER_RULE}")]
    );
    assert_eq!(
        local_database
            .evidence_metadata_records_for_run(MIXED_RUN)
            .expect("replacement evidence metadata can be retrieved"),
        vec![PUBLIC_EVIDENCE_ID.to_owned()]
    );
    assert_eq!(
        local_database
            .score_summary_records_for_run(MIXED_RUN)
            .expect("replacement score summaries can be retrieved"),
        vec![FRAMEWORK.to_owned()]
    );
}

#[test]
fn writing_a_completed_corpus_rejects_an_empty_run_id() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    let error = local_database
        .write_completed_corpus(&consent_corpus())
        .expect_err("a completed corpus without a run id is rejected");

    assert_eq!(
        error.to_string(),
        "local database schema error: completed corpus run_id cannot be empty"
    );
    assert!(
        local_database
            .query_runs()
            .expect("scan runs can be queried after the rejected write")
            .is_empty(),
        "the rejected corpus must not create a scan run"
    );
}

#[test]
fn a_failed_completed_corpus_write_rolls_back_partial_rows() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    let connection = Connection::open(database.path()).expect("the database can be inspected");
    connection
        .execute("DROP TABLE control_results", [])
        .expect("the result table can be removed to force a mid-write failure");
    drop(connection);

    let error = local_database
        .write_completed_corpus(&consent_corpus().with_run_id(SHOPFRONT_RUN))
        .expect_err("the incomplete schema rejects the completed corpus write");
    assert!(
        error.to_string().contains("control_results"),
        "the write should fail on the removed result table: {error}"
    );

    let connection = Connection::open(database.path()).expect("the database can be inspected");
    let run_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
            [SHOPFRONT_RUN],
            |row| row.get(0),
        )
        .expect("scan runs can be counted after the failed write");
    let framework_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM frameworks WHERE id = ?1",
            [FRAMEWORK],
            |row| row.get(0),
        )
        .expect("frameworks can be counted after the failed write");
    assert_eq!(run_count, 0, "the partial scan run must be rolled back");
    assert_eq!(
        framework_count, 0,
        "the partial framework row must be rolled back"
    );
}

#[test]
fn concurrent_writes_to_the_same_run_are_serialized() {
    let database = TempDatabase::new();
    drop(LocalDatabase::open(database.path()).expect("the local database is initialized"));
    write_corpora_concurrently(database.path(), &[CONCURRENT_RUN, CONCURRENT_RUN]);

    let local_database = LocalDatabase::open(database.path()).expect("the local database reopens");
    assert_eq!(
        local_database
            .query_run(CONCURRENT_RUN)
            .expect("the concurrent run can be retrieved"),
        vec![CONCURRENT_RUN.to_owned()]
    );
    assert_eq!(
        local_database
            .control_result_records_for_run(CONCURRENT_RUN)
            .expect("the concurrent run results can be retrieved")
            .len(),
        2
    );
    assert_eq!(
        local_database
            .evidence_metadata_records_for_run(CONCURRENT_RUN)
            .expect("the concurrent run evidence can be retrieved"),
        vec![PUBLIC_EVIDENCE_ID.to_owned()]
    );
    assert_eq!(
        local_database
            .score_summary_records_for_run(CONCURRENT_RUN)
            .expect("the concurrent run score summaries can be retrieved"),
        vec![FRAMEWORK.to_owned()]
    );
}

#[test]
fn concurrent_writes_to_different_runs_are_isolated() {
    let database = TempDatabase::new();
    drop(LocalDatabase::open(database.path()).expect("the local database is initialized"));
    write_corpora_concurrently(database.path(), &[SHOPFRONT_RUN, SHOPFRONT_REPLAY_RUN]);

    let local_database = LocalDatabase::open(database.path()).expect("the local database reopens");
    assert_eq!(
        local_database
            .query_runs()
            .expect("the concurrent runs can be retrieved"),
        vec![SHOPFRONT_RUN.to_owned(), SHOPFRONT_REPLAY_RUN.to_owned()]
    );
    for run_id in [SHOPFRONT_RUN, SHOPFRONT_REPLAY_RUN] {
        assert_eq!(
            local_database
                .evidence_metadata_records_for_run(run_id)
                .expect("the concurrent run evidence can be retrieved"),
            vec![PUBLIC_EVIDENCE_ID.to_owned()]
        );
    }
}

#[test]
fn concurrent_first_writes_apply_schema_migrations_once() {
    let database = TempDatabase::new();
    let barrier = Arc::new(Barrier::new(2));
    let writers = [SHOPFRONT_RUN, SHOPFRONT_REPLAY_RUN]
        .into_iter()
        .map(|run_id| {
            let database_path = database.path().to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut local_database = LocalDatabase::open(database_path)
                    .expect("a concurrent first connection applies migrations");
                local_database
                    .write_completed_corpus(&consent_corpus().with_run_id(run_id))
                    .expect("the first corpus write succeeds after migration");
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        writer
            .join()
            .expect("the concurrent migration writer completes");
    }

    let local_database = LocalDatabase::open(database.path()).expect("the database reopens");
    assert_eq!(
        local_database
            .query_runs()
            .expect("both first runs can be queried"),
        vec![SHOPFRONT_RUN.to_owned(), SHOPFRONT_REPLAY_RUN.to_owned()]
    );
    assert_eq!(
        local_database
            .applied_migrations()
            .expect("the migration ledger can be queried"),
        vec!["0001-initial".to_owned()],
        "the consolidated fresh schema migration should be recorded exactly once"
    );
}

fn write_corpora_concurrently(database_path: &Path, run_ids: &[&str]) {
    let barrier = Arc::new(Barrier::new(run_ids.len()));
    let writers = run_ids
        .iter()
        .map(|run_id| {
            let database_path = database_path.to_owned();
            let run_id = (*run_id).to_owned();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut local_database =
                    LocalDatabase::open(database_path).expect("a concurrent connection opens");
                barrier.wait();
                local_database.write_completed_corpus(&consent_corpus().with_run_id(run_id))
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        writer
            .join()
            .expect("the concurrent writer thread completes")
            .expect("the concurrent corpus write succeeds");
    }
}

#[test]
fn score_summaries_are_scoped_to_runs_with_results() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    local_database
        .write_completed_corpus(&consent_corpus().with_run_id(SHOPFRONT_RUN))
        .expect("the run with results is written");
    let catalog_only_corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(SHOPFRONT_REPLAY_RUN)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        );
    local_database
        .write_completed_corpus(&catalog_only_corpus)
        .expect("the catalog-only run is written");

    assert_eq!(
        local_database
            .score_summary_records_for_run(SHOPFRONT_RUN)
            .expect("the scored run summaries can be retrieved"),
        vec![FRAMEWORK.to_owned()]
    );
    assert!(
        local_database
            .score_summary_records_for_run(SHOPFRONT_REPLAY_RUN)
            .expect("the catalog-only run summaries can be retrieved")
            .is_empty(),
        "a catalog entry without results must not inherit another run's score"
    );
}

fn completed_corpus_examples() -> Vec<CompletedCorpusCase> {
    vec![
        CompletedCorpusCase {
            run: SHOPFRONT_RUN,
            corpus: consent_corpus().with_run_id(SHOPFRONT_RUN),
            framework_count: 1,
            control_count: 1,
            result_count: 2,
            gap_count: 1,
            evidence_count: 1,
            score_count: 1,
        },
        CompletedCorpusCase {
            run: MIXED_RUN,
            corpus: mixed_completed_corpus().with_run_id(MIXED_RUN),
            framework_count: 2,
            control_count: 2,
            result_count: 3,
            gap_count: 2,
            evidence_count: 2,
            score_count: 2,
        },
        CompletedCorpusCase {
            run: CLASSIFIED_EVIDENCE_RUN,
            corpus: classified_evidence_completed_corpus().with_run_id(CLASSIFIED_EVIDENCE_RUN),
            framework_count: 1,
            control_count: 1,
            result_count: 2,
            gap_count: 0,
            evidence_count: 2,
            score_count: 1,
        },
        CompletedCorpusCase {
            run: STORED_RECORD_RUN,
            corpus: stored_record_completed_corpus().with_run_id(STORED_RECORD_RUN),
            framework_count: 1,
            control_count: 1,
            result_count: 1,
            gap_count: 0,
            evidence_count: 1,
            score_count: 1,
        },
    ]
}

fn mixed_completed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_framework(ISO_27001_FRAMEWORK, ISO_27001_VERSION, ISO_27001_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control(
            ISO_27001_FRAMEWORK,
            SSH_CONTROL,
            SSH_CONTROL_TITLE,
            "minor",
            8,
            SSH_CONTROL_REFERENCE,
        )
        .with_control_result(
            FRAMEWORK,
            control_result(
                CONTROL,
                TRACKER_RULE,
                "major",
                Status::Fail,
                PUBLIC_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            FRAMEWORK,
            control_result(CONTROL, CMP_RULE, "major", Status::Pass, PUBLIC_EVIDENCE_ID),
        )
        .with_control_result(
            ISO_27001_FRAMEWORK,
            control_result(
                SSH_CONTROL,
                SSH_RULE,
                "minor",
                Status::Warning,
                SENSITIVE_EVIDENCE_ID,
            ),
        )
        // Public evidence metadata: ev-0001 | dist/main.js |
        // sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad | Public.
        .with_evidence_digest(
            PUBLIC_EVIDENCE_ID,
            "file",
            PUBLIC_EVIDENCE_LOCATOR,
            PUBLIC_EVIDENCE_DIGEST,
        )
        // Sensitive evidence metadata: ev-0008 | config/users.yaml:12 |
        // sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | Sensitive.
        .with_classified_evidence(
            SENSITIVE_EVIDENCE_ID,
            "config",
            SENSITIVE_EVIDENCE_LOCATOR,
            Classification::Sensitive,
            SENSITIVE_EVIDENCE_DIGEST,
        )
}

fn classified_evidence_completed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(
            FRAMEWORK,
            control_result(CONTROL, TRACKER_RULE, "major", Status::Pass, "ev-0007"),
        )
        .with_control_result(
            FRAMEWORK,
            control_result(
                CONTROL,
                CMP_RULE,
                "major",
                Status::Pass,
                SENSITIVE_EVIDENCE_ID,
            ),
        )
        .with_classified_evidence(
            "ev-0007",
            "config",
            ".env.example:3",
            Classification::Secret,
            PUBLIC_EVIDENCE_DIGEST,
        )
        .with_classified_evidence(
            SENSITIVE_EVIDENCE_ID,
            "config",
            SENSITIVE_EVIDENCE_LOCATOR,
            Classification::Sensitive,
            SENSITIVE_EVIDENCE_DIGEST,
        )
}

fn stored_record_completed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(
            FRAMEWORK,
            control_result(CONTROL, CMP_RULE, "major", Status::Pass, STORED_EVIDENCE_ID),
        )
        .with_evidence_digest(
            STORED_EVIDENCE_ID,
            STORED_EVIDENCE_KIND,
            STORED_EVIDENCE_LOCATION,
            STORED_EVIDENCE_INTEGRITY,
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
        builder = builder.reason("Observed during the completed corpus run.");
    }
    builder
        .build()
        .expect("the completed corpus fixture result validates")
}

fn create_legacy_completed_corpus_schema(path: &Path) {
    fs::create_dir_all(path.parent().expect("database path has a parent"))
        .expect("legacy database parent can be created");
    let connection = Connection::open(path).expect("legacy database can be created");
    connection
        .execute_batch(
            "
            CREATE TABLE scan_runs (id TEXT PRIMARY KEY);
            CREATE TABLE frameworks (
              id TEXT PRIMARY KEY,
              version TEXT NOT NULL
            );
            CREATE TABLE controls (id TEXT PRIMARY KEY);
            CREATE TABLE control_results (id TEXT PRIMARY KEY);
            CREATE TABLE compliance_gaps (id TEXT PRIMARY KEY);
            CREATE TABLE evidence_metadata (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              digest TEXT NOT NULL
            );
            CREATE TABLE score_summaries (id TEXT PRIMARY KEY);
            CREATE TABLE exports (id TEXT PRIMARY KEY);
            CREATE TABLE schema_migrations (
              version INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_migrations(version, name)
            VALUES (1, '0001-initial');
            INSERT INTO scan_runs(id) VALUES ('legacy-run');
            INSERT INTO frameworks(id, version) VALUES ('legacy-framework', 'legacy-version');
            INSERT INTO controls(id) VALUES ('legacy-control');
            INSERT INTO evidence_metadata(id, run_id, digest)
            VALUES ('legacy-evidence', 'legacy-run', 'sha256:legacy');
            PRAGMA user_version = 1;
            ",
        )
        .expect("legacy schema can be seeded");
}

fn assert_legacy_rows_are_preserved(path: &Path) {
    let connection = Connection::open(path).expect("database can be inspected");
    assert_eq!(
        legacy_row_count(&connection, "scan_runs", "legacy-run"),
        1,
        "legacy scan run remains present"
    );
    assert_eq!(
        legacy_row_count(&connection, "frameworks", "legacy-framework"),
        1,
        "legacy framework remains present"
    );
    assert_eq!(
        legacy_row_count(&connection, "controls", "legacy-control"),
        1,
        "legacy control remains present"
    );
    assert_eq!(
        legacy_row_count(&connection, "evidence_metadata", "legacy-evidence"),
        1,
        "legacy evidence remains present"
    );
    let legacy_link_count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM run_evidence_links
             WHERE run_id = 'legacy-run' AND evidence_id = 'legacy-evidence'",
            [],
            |row| row.get(0),
        )
        .expect("legacy evidence link can be inspected");
    assert_eq!(
        legacy_link_count, 1,
        "legacy evidence remains linked to its run"
    );
}

fn assert_shared_evidence_keeps_both_run_links(path: &Path) {
    let connection = Connection::open(path).expect("database can be inspected");
    let legacy_owner: String = connection
        .query_row(
            "SELECT run_id FROM evidence_metadata WHERE id = ?1",
            [PUBLIC_EVIDENCE_ID],
            |row| row.get(0),
        )
        .expect("the legacy evidence owner can be inspected");
    assert_eq!(
        legacy_owner, SHOPFRONT_RUN,
        "a later run must not replace the first legacy owner"
    );
    let link_count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM run_evidence_links
             WHERE evidence_id = ?1
               AND run_id IN (?2, ?3)",
            [PUBLIC_EVIDENCE_ID, SHOPFRONT_RUN, SHOPFRONT_REPLAY_RUN],
            |row| row.get(0),
        )
        .expect("the shared evidence links can be inspected");
    assert_eq!(link_count, 2, "both current run links must be preserved");
}

fn legacy_row_count(connection: &Connection, table_name: &str, id: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table_name} WHERE id = ?1");
    connection
        .query_row(&sql, [id], |row| row.get(0))
        .expect("legacy row count can be inspected")
}
