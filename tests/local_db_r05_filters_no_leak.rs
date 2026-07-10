// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 -- result filters do not leak unrelated records. Covers issue #353.

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
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
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
const HOST_RULE: &str = "host.ssh.detect-permit-root-login";
const MIXED_EVIDENCE_ID: &str = "ev-0001";
const MIXED_EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const HOST_EVIDENCE_ID: &str = "ev-0008";
const HOST_EVIDENCE_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const CLASSIFIED_EVIDENCE_ID: &str = "ev-0007";
const CLASSIFIED_EVIDENCE_DIGEST: &str =
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
            "sovri-agent-mat98-r05-filters-no-leak-{}-{now}-{unique}",
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
    run_id: String,
    status: String,
}

#[allow(dead_code)]
impl ResultQueryRow {
    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn status(&self) -> &str {
        &self.status
    }
}

#[allow(dead_code)]
trait LocalDatabaseResultQueries {
    fn query_results(
        &self,
        _run_id: &str,
        _control_id: &str,
        _status: &str,
    ) -> Result<Vec<ResultQueryRow>, LocalDatabaseError> {
        panic!("LocalDatabase::query_results is not implemented")
    }
}

impl LocalDatabaseResultQueries for LocalDatabase {}

#[test]
fn filters_do_not_leak_unrelated_records() {
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

    // When the operator queries results for run "mixed-2026-06-24", control "consent.tracker.prior-consent", and status "FAIL".
    let results = local_database
        .query_results(MIXED_RUN_ID, CONSENT_CONTROL_ID, "FAIL")
        .expect("the filtered result set can be queried");

    // Then no result with status "PASS" is returned.
    assert!(results.iter().all(|result| result.status() != "PASS"));

    // And no result with status "WARNING" is returned.
    assert!(results.iter().all(|result| result.status() != "WARNING"));

    // And no result from run "classified-evidence-2026-06-24" is returned.
    assert!(results
        .iter()
        .all(|result| result.run_id() != CLASSIFIED_RUN_ID));
}

fn mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(MIXED_RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_framework(ISO_FRAMEWORK_ID, ISO_FRAMEWORK_VERSION, ISO_FRAMEWORK_URL)
        .with_control(
            FRAMEWORK_ID,
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
            FRAMEWORK_ID,
            control_result(
                CONSENT_CONTROL_ID,
                TRACKER_RULE,
                Status::Fail,
                "major",
                8,
                MIXED_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            FRAMEWORK_ID,
            control_result(
                CONSENT_CONTROL_ID,
                CMP_RULE,
                Status::Pass,
                "major",
                8,
                MIXED_EVIDENCE_ID,
            ),
        )
        .with_control_result(
            ISO_FRAMEWORK_ID,
            control_result(
                HOST_CONTROL_ID,
                HOST_RULE,
                Status::Warning,
                "minor",
                3,
                HOST_EVIDENCE_ID,
            ),
        )
        .with_evidence_digest(
            MIXED_EVIDENCE_ID,
            "file",
            "dist/main.js",
            MIXED_EVIDENCE_DIGEST,
        )
        .with_evidence_digest(
            HOST_EVIDENCE_ID,
            "config",
            "config/users.yaml:12",
            HOST_EVIDENCE_DIGEST,
        )
}

fn classified_evidence_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(CLASSIFIED_RUN_ID)
        .with_framework(FRAMEWORK_ID, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK_ID,
            CONSENT_CONTROL_ID,
            CONSENT_CONTROL_TITLE,
            "major",
            8,
            CONSENT_CONTROL_REFERENCE,
        )
        .with_control_result(
            FRAMEWORK_ID,
            control_result(
                CONSENT_CONTROL_ID,
                TRACKER_RULE,
                Status::Fail,
                "major",
                8,
                CLASSIFIED_EVIDENCE_ID,
            ),
        )
        .with_classified_evidence(
            CLASSIFIED_EVIDENCE_ID,
            "secret",
            ".env.example:3",
            Classification::Secret,
            CLASSIFIED_EVIDENCE_DIGEST,
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
