// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 -- gaps can be retrieved by run, status, and severity. Covers issue
//! #350.

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
            "sovri-agent-mat98-r05-gaps-query-{}-{now}-{unique}",
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
struct GapQueryRow {
    control_id: String,
    rule_id: String,
    status: String,
}

#[allow(dead_code)]
impl GapQueryRow {
    fn control_id(&self) -> &str {
        &self.control_id
    }

    fn rule_id(&self) -> &str {
        &self.rule_id
    }

    fn status(&self) -> &str {
        &self.status
    }
}

#[allow(dead_code)]
trait LocalDatabaseGapQueries {
    fn query_gaps(
        &self,
        _run_id: &str,
        _status: &str,
        _severity: &str,
    ) -> Result<Vec<GapQueryRow>, LocalDatabaseError> {
        panic!("LocalDatabase::query_gaps is not implemented")
    }
}

impl LocalDatabaseGapQueries for LocalDatabase {}

#[test]
fn gaps_can_be_retrieved_by_run_status_and_severity() {
    let database = TempDatabase::new();

    // Given an open local database at "./tmp/sovri-mat-98.db".
    let mut local_database =
        LocalDatabase::open(database.path()).expect("the local database opens");

    // And the "mixed-2026-06-24" corpus has been written to SQLite:
    local_database
        .write_completed_corpus(&mixed_corpus())
        .expect("the mixed corpus write succeeds");

    // And the "classified-evidence-2026-06-24" corpus has been written to SQLite with evidence "ev-0007".
    local_database
        .write_completed_corpus(&classified_evidence_corpus())
        .expect("the classified evidence corpus write succeeds");

    for example in gap_query_examples() {
        // When the operator queries gaps for run "mixed-2026-06-24", status "<status>", and severity "<severity>".
        let gaps = local_database
            .query_gaps(MIXED_RUN_ID, example.status, example.severity)
            .expect("the gaps can be queried");

        // Then exactly 1 gap is returned.
        assert_eq!(gaps.len(), 1);
        let gap = gaps.first().expect("the single gap is returned");

        // And the gap has control "<control>".
        assert_eq!(gap.control_id(), example.control);

        // And the gap has rule "<rule>".
        assert_eq!(gap.rule_id(), example.rule);

        // And the gap does not include status "PASS".
        assert!(
            gaps.iter().all(|gap| gap.status() != "PASS"),
            "no returned gap has PASS status"
        );
    }
}

struct GapQueryExample {
    status: &'static str,
    severity: &'static str,
    control: &'static str,
    rule: &'static str,
}

fn gap_query_examples() -> [GapQueryExample; 2] {
    [
        GapQueryExample {
            status: "FAIL",
            severity: "major",
            control: CONSENT_CONTROL_ID,
            rule: TRACKER_RULE,
        },
        GapQueryExample {
            status: "WARNING",
            severity: "minor",
            control: HOST_CONTROL_ID,
            rule: SSH_RULE,
        },
    ]
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
            "classified/evidence.env",
            Classification::Secret,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
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
