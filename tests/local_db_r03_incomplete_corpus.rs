// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 -- an incomplete corpus is not committed as a completed run. Covers
//! issue #343.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
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

fn create_version_1_database_with_legacy_run_id(path: &Path) {
    fs::create_dir_all(path.parent().expect("database path has a parent"))
        .expect("database parent can be created");
    let connection = Connection::open(path).expect("version 1 database can be created");
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
            PRAGMA user_version = 1;
            ",
        )
        .expect("version 1 schema can be seeded");
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
    assert_row_absent(database.path(), TestTable::ScanRuns, MIXED_RUN);

    // And no framework row for "gdpr-eprivacy" is committed for run "mixed-2026-06-24".
    assert_row_absent(database.path(), TestTable::Frameworks, GDPR_FRAMEWORK);

    // And no control row for "consent.tracker.prior-consent" is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), TestTable::Controls);

    // And no result row for "consent.detect-trackers-without-consent-evidence" is committed.
    assert_table_empty(database.path(), TestTable::ControlResults);

    // And no partial compliance gap for "consent.tracker.prior-consent" is committed.
    assert_table_empty(database.path(), TestTable::ComplianceGaps);

    // And no evidence metadata row for "ev-0001" is committed for run "mixed-2026-06-24".
    assert_row_absent(
        database.path(),
        TestTable::EvidenceMetadata,
        PUBLIC_EVIDENCE_ID,
    );

    // And no score summary is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), TestTable::ScoreSummaries);

    // And no export record is committed for run "mixed-2026-06-24".
    assert_table_empty(database.path(), TestTable::Exports);
}

#[test]
fn framework_metadata_without_controls_or_results_is_not_committed() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    let corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN)
        .with_framework(
            GDPR_FRAMEWORK,
            "2016-679",
            "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        );

    let write_result = local_database.write_completed_corpus(&corpus);

    assert!(
        write_result.is_err(),
        "framework metadata alone is not a completed corpus"
    );
    assert_row_absent(database.path(), TestTable::ScanRuns, MIXED_RUN);
    assert_row_absent(database.path(), TestTable::Frameworks, GDPR_FRAMEWORK);
    assert_table_empty(database.path(), TestTable::Controls);
    assert_table_empty(database.path(), TestTable::ControlResults);
    assert_table_empty(database.path(), TestTable::ScoreSummaries);
    assert_table_empty(database.path(), TestTable::Exports);
}

#[test]
fn corpus_with_no_framework_metadata_is_not_committed() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    let corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN)
        .with_control(
            GDPR_FRAMEWORK,
            CONSENT_CONTROL,
            CONSENT_TITLE,
            "major",
            8,
            CONSENT_REFERENCE,
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
        .with_evidence_digest(
            PUBLIC_EVIDENCE_ID,
            "file",
            "dist/main.js",
            PUBLIC_EVIDENCE_DIGEST,
        );

    let write_result = local_database.write_completed_corpus(&corpus);

    assert!(
        write_result.is_err(),
        "a completed corpus needs framework metadata for referenced frameworks"
    );
    assert_row_absent(database.path(), TestTable::ScanRuns, MIXED_RUN);
    assert_table_empty(database.path(), TestTable::Frameworks);
    assert_table_empty(database.path(), TestTable::Controls);
    assert_table_empty(database.path(), TestTable::ControlResults);
    assert_row_absent(
        database.path(),
        TestTable::EvidenceMetadata,
        PUBLIC_EVIDENCE_ID,
    );
    assert_table_empty(database.path(), TestTable::Exports);
}

#[test]
fn completed_corpus_with_evidence_writes_to_upgraded_legacy_run_id_schema() {
    let database = TempDatabase::new();
    create_version_1_database_with_legacy_run_id(database.path());
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the legacy database upgrades");
    assert!(
        local_database.schema_version() >= 2,
        "the legacy database should include the run-evidence migration"
    );
    let corpus = complete_gdpr_corpus();

    local_database
        .write_completed_corpus(&corpus)
        .expect("completed corpora with evidence write on upgraded legacy schemas");

    assert_row_present(database.path(), TestTable::ScanRuns, MIXED_RUN);
    assert_evidence_metadata_linked_to_run(
        database.path(),
        PUBLIC_EVIDENCE_ID,
        MIXED_RUN,
        PUBLIC_EVIDENCE_DIGEST,
    );
    assert_run_evidence_link_present(database.path(), MIXED_RUN, PUBLIC_EVIDENCE_ID);
}

fn complete_gdpr_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN)
        .with_framework(
            GDPR_FRAMEWORK,
            "2016-679",
            "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        )
        .with_control(
            GDPR_FRAMEWORK,
            CONSENT_CONTROL,
            CONSENT_TITLE,
            "major",
            8,
            CONSENT_REFERENCE,
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
        .with_evidence_digest(
            PUBLIC_EVIDENCE_ID,
            "file",
            "dist/main.js",
            PUBLIC_EVIDENCE_DIGEST,
        )
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

#[derive(Clone, Copy)]
enum TestTable {
    ScanRuns,
    Frameworks,
    Controls,
    ControlResults,
    ComplianceGaps,
    EvidenceMetadata,
    ScoreSummaries,
    Exports,
}

impl TestTable {
    const fn label(self) -> &'static str {
        match self {
            TestTable::ScanRuns => "scan_runs",
            TestTable::Frameworks => "frameworks",
            TestTable::Controls => "controls",
            TestTable::ControlResults => "control_results",
            TestTable::ComplianceGaps => "compliance_gaps",
            TestTable::EvidenceMetadata => "evidence_metadata",
            TestTable::ScoreSummaries => "score_summaries",
            TestTable::Exports => "exports",
        }
    }

    const fn count_by_id_sql(self) -> &'static str {
        match self {
            TestTable::ScanRuns => "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
            TestTable::Frameworks => "SELECT COUNT(*) FROM frameworks WHERE id = ?1",
            TestTable::Controls => "SELECT COUNT(*) FROM controls WHERE id = ?1",
            TestTable::ControlResults => "SELECT COUNT(*) FROM control_results WHERE id = ?1",
            TestTable::ComplianceGaps => "SELECT COUNT(*) FROM compliance_gaps WHERE id = ?1",
            TestTable::EvidenceMetadata => "SELECT COUNT(*) FROM evidence_metadata WHERE id = ?1",
            TestTable::ScoreSummaries => "SELECT COUNT(*) FROM score_summaries WHERE id = ?1",
            TestTable::Exports => "SELECT COUNT(*) FROM exports WHERE id = ?1",
        }
    }

    const fn count_all_sql(self) -> &'static str {
        match self {
            TestTable::ScanRuns => "SELECT COUNT(*) FROM scan_runs",
            TestTable::Frameworks => "SELECT COUNT(*) FROM frameworks",
            TestTable::Controls => "SELECT COUNT(*) FROM controls",
            TestTable::ControlResults => "SELECT COUNT(*) FROM control_results",
            TestTable::ComplianceGaps => "SELECT COUNT(*) FROM compliance_gaps",
            TestTable::EvidenceMetadata => "SELECT COUNT(*) FROM evidence_metadata",
            TestTable::ScoreSummaries => "SELECT COUNT(*) FROM score_summaries",
            TestTable::Exports => "SELECT COUNT(*) FROM exports",
        }
    }
}

fn assert_row_absent(path: &Path, table: TestTable, id: &str) {
    assert_eq!(
        row_count(path, table, id),
        0,
        "{} should not contain row {id:?}",
        table.label()
    );
}

fn assert_row_present(path: &Path, table: TestTable, id: &str) {
    assert_eq!(
        row_count(path, table, id),
        1,
        "{} should contain row {id:?}",
        table.label()
    );
}

fn assert_table_empty(path: &Path, table: TestTable) {
    assert_eq!(
        table_row_count(path, table),
        0,
        "{} should remain empty after the rejected write",
        table.label()
    );
}

fn row_count(path: &Path, table: TestTable, id: &str) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(table.count_by_id_sql(), [id], |row| row.get(0))
        .expect("row count can be inspected")
}

fn table_row_count(path: &Path, table: TestTable) -> i64 {
    let connection = Connection::open(path).expect("the database can be inspected");
    connection
        .query_row(table.count_all_sql(), [], |row| row.get(0))
        .expect("table row count can be inspected")
}

fn assert_evidence_metadata_linked_to_run(
    path: &Path,
    evidence_id: &str,
    run_id: &str,
    digest: &str,
) {
    let connection = Connection::open(path).expect("the database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM evidence_metadata
             WHERE id = ?1 AND run_id = ?2 AND digest = ?3",
            params![evidence_id, run_id, digest],
            |row| row.get(0),
        )
        .expect("legacy evidence metadata link can be inspected");
    assert_eq!(count, 1, "evidence metadata should preserve run_id");
}

fn assert_run_evidence_link_present(path: &Path, run_id: &str, evidence_id: &str) {
    let connection = Connection::open(path).expect("the database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM run_evidence_links
             WHERE run_id = ?1 AND evidence_id = ?2",
            params![run_id, evidence_id],
            |row| row.get(0),
        )
        .expect("run evidence link can be inspected");
    assert_eq!(count, 1, "run_evidence_links should record new evidence");
}
