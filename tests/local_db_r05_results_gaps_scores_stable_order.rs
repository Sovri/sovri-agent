// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 -- results, gaps, and scores use stable ordering. Covers issue #352.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::{LocalDatabase, LocalDatabaseError};
use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

const MIXED_RUN_ID: &str = "mixed-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const GDPR_FRAMEWORK_ID: &str = "gdpr-eprivacy";
const GDPR_FRAMEWORK_VERSION: &str = "2016-679";
const GDPR_FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const ISO_FRAMEWORK_ID: &str = "iso-27001";
const ISO_FRAMEWORK_VERSION: &str = "2022";
const ISO_FRAMEWORK_URL: &str = "https://www.iso.org/standard/27001";
const CONSENT_CONTROL_ID: &str = "consent.tracker.prior-consent";
const CONSENT_CONTROL_TITLE: &str = "Prior consent for tracker access";
const CONSENT_CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const HOST_CONTROL_ID: &str = "host.ssh.permit-root-login";
const HOST_CONTROL_TITLE: &str = "SSH root login is disabled";
const HOST_CONTROL_REFERENCE: &str = "iso-27001:2022:A.8.3";
const SSH_RULE: &str = "host.ssh.detect-permit-root-login";
const CONSENT_EVIDENCE_ID: &str = "ev-0001";
const CONSENT_EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SSH_EVIDENCE_ID: &str = "ev-0008";
const SSH_EVIDENCE_DIGEST: &str =
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
            "sovri-agent-mat98-r05-stable-result-score-order-{}-{now}-{unique}",
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

#[allow(dead_code)]
struct ResultQueryRow {
    control_id: String,
    rule_id: String,
}

#[allow(dead_code)]
impl ResultQueryRow {
    fn control_id(&self) -> &str {
        &self.control_id
    }

    fn rule_id(&self) -> &str {
        &self.rule_id
    }
}

#[allow(dead_code)]
struct ScoreSummaryQueryRow {
    framework_id: String,
}

#[allow(dead_code)]
impl ScoreSummaryQueryRow {
    fn framework_id(&self) -> &str {
        &self.framework_id
    }
}

#[allow(dead_code)]
trait LocalDatabaseStableOrderQueries {
    fn query_results(&self, _run_id: &str) -> Result<Vec<ResultQueryRow>, LocalDatabaseError> {
        panic!("LocalDatabase::query_results is not implemented")
    }

    fn query_score_summaries(
        &self,
        _run_id: &str,
    ) -> Result<Vec<ScoreSummaryQueryRow>, LocalDatabaseError> {
        panic!("LocalDatabase::query_score_summaries is not implemented")
    }
}

impl LocalDatabaseStableOrderQueries for LocalDatabase {}

#[test]
fn results_gaps_and_scores_use_stable_ordering() {
    let database = TempDatabase::new();

    // Given the "mixed-2026-06-24" results were written in reverse input order.
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    local_database
        .write_completed_corpus(&reverse_order_mixed_corpus())
        .expect("the reverse-order mixed corpus write succeeds");

    // When the operator queries all results for run "mixed-2026-06-24".
    let results = local_database
        .query_results(MIXED_RUN_ID)
        .expect("the result rows can be queried");

    // Then the result order is:
    assert_eq!(
        results
            .iter()
            .map(|row| (row.control_id(), row.rule_id()))
            .collect::<Vec<_>>(),
        vec![
            (CONSENT_CONTROL_ID, CMP_RULE),
            (CONSENT_CONTROL_ID, TRACKER_RULE),
            (HOST_CONTROL_ID, SSH_RULE),
        ]
    );

    // When the operator queries score summaries for run "mixed-2026-06-24".
    let score_summaries = local_database
        .query_score_summaries(MIXED_RUN_ID)
        .expect("the score summaries can be queried");

    // Then the score summary order is:
    assert_eq!(
        score_summaries
            .iter()
            .map(|row| row.framework_id().to_owned())
            .collect::<Vec<_>>(),
        vec![GDPR_FRAMEWORK_ID.to_owned(), ISO_FRAMEWORK_ID.to_owned()]
    );
}

#[test]
fn unmatched_or_empty_run_queries_return_stable_empty_results() {
    let database = TempDatabase::new();
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");
    local_database
        .write_completed_corpus(&reverse_order_mixed_corpus())
        .expect("the reverse-order mixed corpus write succeeds");

    for run_id in ["", "missing-2026-06-24"] {
        assert!(
            local_database
                .query_results(run_id)
                .expect("the result rows can be queried")
                .is_empty(),
            "no results are returned for run id {run_id:?}"
        );
        assert!(
            local_database
                .query_score_summaries(run_id)
                .expect("the score summaries can be queried")
                .is_empty(),
            "no score summaries are returned for run id {run_id:?}"
        );
    }
}

#[test]
fn migrated_result_and_score_rows_remain_queryable_by_run() {
    let database = TempDatabase::new();
    create_legacy_version_4_database_without_query_scope(database.path());

    let local_database =
        LocalDatabase::open(database.path()).expect("the version 4 database reopens");

    let results = local_database
        .query_results(MIXED_RUN_ID)
        .expect("the migrated result rows can be queried");
    assert_eq!(
        results
            .iter()
            .map(|row| (row.control_id(), row.rule_id()))
            .collect::<Vec<_>>(),
        vec![
            (CONSENT_CONTROL_ID, CMP_RULE),
            (CONSENT_CONTROL_ID, TRACKER_RULE),
            (HOST_CONTROL_ID, SSH_RULE),
        ]
    );

    let score_summaries = local_database
        .query_score_summaries(MIXED_RUN_ID)
        .expect("the migrated score summaries can be queried");
    assert_eq!(
        score_summaries
            .iter()
            .map(|row| row.framework_id().to_owned())
            .collect::<Vec<_>>(),
        vec![GDPR_FRAMEWORK_ID.to_owned(), ISO_FRAMEWORK_ID.to_owned()]
    );
}

#[test]
fn partial_migration_run_ids_are_repaired_from_stable_result_ids() {
    let database = TempDatabase::new();
    create_legacy_version_4_database_without_query_scope(database.path());
    seed_partial_query_scope_migration_state(database.path());

    let local_database =
        LocalDatabase::open(database.path()).expect("the partial migration database reopens");

    assert!(
        local_database
            .query_results("wrong-run")
            .expect("wrong-run results can be queried")
            .is_empty(),
        "stale partial-migration run ids are repaired"
    );
    assert!(
        local_database
            .query_results("")
            .expect("empty-run results can be queried")
            .is_empty(),
        "malformed legacy result ids are not exposed as empty-run results"
    );
    assert_eq!(
        local_database
            .query_results(MIXED_RUN_ID)
            .expect("the repaired result rows can be queried")
            .len(),
        3
    );
}

fn reverse_order_mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN_ID)
        .with_framework(ISO_FRAMEWORK_ID, ISO_FRAMEWORK_VERSION, ISO_FRAMEWORK_URL)
        .with_framework(
            GDPR_FRAMEWORK_ID,
            GDPR_FRAMEWORK_VERSION,
            GDPR_FRAMEWORK_URL,
        )
        .with_control(
            ISO_FRAMEWORK_ID,
            HOST_CONTROL_ID,
            HOST_CONTROL_TITLE,
            "minor",
            3,
            HOST_CONTROL_REFERENCE,
        )
        .with_control(
            GDPR_FRAMEWORK_ID,
            CONSENT_CONTROL_ID,
            CONSENT_CONTROL_TITLE,
            "major",
            8,
            CONSENT_CONTROL_REFERENCE,
        )
        .with_control_result(
            ISO_FRAMEWORK_ID,
            control_result(
                HOST_CONTROL_ID,
                SSH_RULE,
                Status::Warning,
                "minor",
                3,
                SSH_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            GDPR_FRAMEWORK_ID,
            control_result(
                CONSENT_CONTROL_ID,
                TRACKER_RULE,
                Status::Fail,
                "major",
                8,
                CONSENT_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            GDPR_FRAMEWORK_ID,
            control_result(
                CONSENT_CONTROL_ID,
                CMP_RULE,
                Status::Pass,
                "major",
                8,
                CONSENT_EVIDENCE_ID,
            ),
        )
        .with_evidence_digest(
            SSH_EVIDENCE_ID,
            "config",
            "config/users.yaml:12",
            SSH_EVIDENCE_DIGEST,
        )
        .with_evidence_digest(
            CONSENT_EVIDENCE_ID,
            "file",
            "dist/main.js",
            CONSENT_EVIDENCE_DIGEST,
        )
}

fn create_legacy_version_4_database_without_query_scope(path: &Path) {
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
            CREATE TABLE control_results (
              id TEXT PRIMARY KEY,
              control_id TEXT NOT NULL,
              rule_id TEXT NOT NULL,
              evidence_id TEXT NOT NULL
            );
            CREATE TABLE compliance_gaps (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              status TEXT NOT NULL,
              severity TEXT NOT NULL,
              control_id TEXT NOT NULL,
              rule_id TEXT NOT NULL
            );
            CREATE TABLE evidence_metadata (
              id TEXT PRIMARY KEY,
              digest TEXT NOT NULL,
              locator TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE score_summaries (id TEXT PRIMARY KEY);
            CREATE TABLE exports (id TEXT PRIMARY KEY);
            CREATE TABLE schema_migrations (
              version INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO schema_migrations(version, name)
            VALUES
              (1, '0001-initial'),
              (2, '0002-run-evidence-links'),
              (3, '0003-gap-query-filters'),
              (4, '0004-evidence-locators');
            PRAGMA user_version = 4;
            ",
        )
        .expect("legacy version 4 schema can be seeded");
    for framework_id in [ISO_FRAMEWORK_ID, GDPR_FRAMEWORK_ID] {
        connection
            .execute(
                "INSERT INTO score_summaries(id) VALUES (?1)",
                params![framework_id],
            )
            .expect("legacy score summary can be seeded");
    }
    for (framework_id, control_id, rule_id, evidence_id) in [
        (ISO_FRAMEWORK_ID, HOST_CONTROL_ID, SSH_RULE, SSH_EVIDENCE_ID),
        (
            GDPR_FRAMEWORK_ID,
            CONSENT_CONTROL_ID,
            TRACKER_RULE,
            CONSENT_EVIDENCE_ID,
        ),
        (
            GDPR_FRAMEWORK_ID,
            CONSENT_CONTROL_ID,
            CMP_RULE,
            CONSENT_EVIDENCE_ID,
        ),
    ] {
        connection
            .execute(
                "INSERT INTO control_results(id, control_id, rule_id, evidence_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    result_row_id(MIXED_RUN_ID, framework_id, control_id, rule_id),
                    control_id,
                    rule_id,
                    evidence_id
                ],
            )
            .expect("legacy control result can be seeded");
    }
}

fn result_row_id(run_id: &str, framework_id: &str, control_id: &str, rule_id: &str) -> String {
    format!(
        "{}:{run_id}:{}:{framework_id}:{}:{control_id}:{rule_id}",
        run_id.len(),
        framework_id.len(),
        control_id.len()
    )
}

fn seed_partial_query_scope_migration_state(path: &Path) {
    let connection = Connection::open(path).expect("legacy database can be reopened");
    connection
        .execute(
            "ALTER TABLE control_results
             ADD COLUMN run_id TEXT NOT NULL DEFAULT 'wrong-run'",
            [],
        )
        .expect("partial migration run_id column can be seeded");
    connection
        .execute(
            "INSERT INTO control_results(id, run_id, control_id, rule_id, evidence_id)
             VALUES ('malformed-result-row', '', 'malformed-control', 'malformed-rule', 'malformed-evidence')",
            [],
        )
        .expect("malformed legacy control result can be seeded");
}

fn control_result(
    control_id: &str,
    rule_id: &str,
    status: Status,
    severity: &str,
    weight: u32,
    evidence_id: &str,
) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity(severity)
        .weight(weight)
        .evidence_refs([evidence_id])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the R-05 stable ordering corpus.");
    }
    builder
        .build()
        .expect("the R-05 stable ordering result validates")
}
