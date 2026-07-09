// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 -- unmatched filters return stable empty results. Covers issue #354.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, LocalDatabaseError};
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{ControlResult, Status};

const MIXED_RUN_ID: &str = "mixed-2026-06-24";
const CLASSIFIED_RUN_ID: &str = "classified-evidence-2026-06-24";
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
const CLASSIFIED_EVIDENCE_ID: &str = "ev-0007";

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
            "sovri-agent-mat98-r05-unmatched-empty-{}-{now}-{unique}",
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
trait LocalDatabaseRunLookup {
    fn query_run(&self, _run_id: &str) -> Result<Vec<String>, LocalDatabaseError> {
        panic!("LocalDatabase::query_run is not implemented")
    }
}

impl LocalDatabaseRunLookup for LocalDatabase {}

#[test]
fn unmatched_filters_return_a_stable_empty_result() {
    let database = TempDatabase::new();

    // Given an open local database at "./tmp/sovri-mat-98.db".
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // And the "mixed-2026-06-24" corpus has been written to SQLite.
    local_database
        .write_completed_corpus(&mixed_corpus())
        .expect("the mixed corpus write succeeds");

    // And the "classified-evidence-2026-06-24" corpus has been written to SQLite with evidence "ev-0007".
    local_database
        .write_completed_corpus(&classified_evidence_corpus())
        .expect("the classified evidence corpus write succeeds");

    for example in unmatched_query_examples() {
        // When the operator queries "<query>" with unmatched value "<value>".
        let first =
            query_values(&local_database, &example).expect("the unmatched filter query succeeds");

        // Then an empty result list is returned.
        assert!(first.is_empty(), "{} returns no rows", example.query);

        // And no unrelated row from "mixed-2026-06-24" is returned.
        assert!(first.iter().all(|value| value != MIXED_RUN_ID));

        // And repeating the same query returns an empty result list again.
        let second = query_values(&local_database, &example)
            .expect("the unmatched filter query can be repeated");
        assert!(second.is_empty(), "{} stays empty", example.query);
        assert_eq!(second, first);
    }
}

#[derive(Clone, Copy)]
enum QueryKind {
    Run,
    ControlResults,
    ResultStatus,
    GapSeverity,
    EvidenceDigest,
}

struct UnmatchedQuery {
    kind: QueryKind,
    query: &'static str,
    value: &'static str,
}

fn unmatched_query_examples() -> [UnmatchedQuery; 5] {
    [
        UnmatchedQuery {
            kind: QueryKind::Run,
            query: "run",
            value: "missing-2026-06-24",
        },
        UnmatchedQuery {
            kind: QueryKind::ControlResults,
            query: "control results",
            value: "host.unknown.control",
        },
        UnmatchedQuery {
            kind: QueryKind::ResultStatus,
            query: "result status",
            value: "ERROR",
        },
        UnmatchedQuery {
            kind: QueryKind::GapSeverity,
            query: "gap severity",
            value: "critical",
        },
        UnmatchedQuery {
            kind: QueryKind::EvidenceDigest,
            query: "evidence digest",
            value: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
    ]
}

fn query_values(
    database: &LocalDatabase,
    example: &UnmatchedQuery,
) -> Result<Vec<String>, LocalDatabaseError> {
    match example.kind {
        QueryKind::Run => database.query_run(example.value),
        QueryKind::ControlResults => database
            .query_results(MIXED_RUN_ID, example.value, "FAIL")
            .map(|rows| rows.iter().map(|row| row.run_id().to_owned()).collect()),
        QueryKind::ResultStatus => database
            .query_results(MIXED_RUN_ID, CONSENT_CONTROL_ID, example.value)
            .map(|rows| rows.iter().map(|row| row.run_id().to_owned()).collect()),
        QueryKind::GapSeverity => database
            .query_gaps(MIXED_RUN_ID, "FAIL", example.value)
            .map(|rows| rows.iter().map(|row| row.control_id().to_owned()).collect()),
        QueryKind::EvidenceDigest => database
            .query_evidence("digest", example.value)
            .map(|rows| rows.iter().map(|row| row.id().to_owned()).collect()),
    }
}

fn mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN_ID)
        .with_framework(
            GDPR_FRAMEWORK_ID,
            GDPR_FRAMEWORK_VERSION,
            GDPR_FRAMEWORK_URL,
        )
        .with_framework(ISO_FRAMEWORK_ID, ISO_FRAMEWORK_VERSION, ISO_FRAMEWORK_URL)
        .with_control(
            GDPR_FRAMEWORK_ID,
            CONSENT_CONTROL_ID,
            CONSENT_CONTROL_TITLE,
            "major",
            8,
            CONSENT_CONTROL_REFERENCE,
        )
        .with_control(
            ISO_FRAMEWORK_ID,
            HOST_CONTROL_ID,
            HOST_CONTROL_TITLE,
            "minor",
            3,
            HOST_CONTROL_REFERENCE,
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
        .with_evidence_digest(
            CONSENT_EVIDENCE_ID,
            "file",
            "dist/main.js",
            CONSENT_EVIDENCE_DIGEST,
        )
        .with_evidence_digest(
            SSH_EVIDENCE_ID,
            "config",
            "config/users.yaml:12",
            SSH_EVIDENCE_DIGEST,
        )
}

fn classified_evidence_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(CLASSIFIED_RUN_ID)
        .with_classified_evidence(
            CLASSIFIED_EVIDENCE_ID,
            "secret",
            ".env.example:3",
            Classification::Secret,
            CONSENT_EVIDENCE_DIGEST,
        )
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
        builder = builder.reason("Observed during the R-05 query corpus.");
    }
    builder.build().expect("the R-05 result validates")
}
