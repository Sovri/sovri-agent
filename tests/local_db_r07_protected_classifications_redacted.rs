// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 -- every protected classification has one redacted projection. Covers #361.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, LocalDatabaseEvidence};
use sovri_agent::matrix::Corpus;
use sovri_sdk::{Classification, Evidence, EvidenceKind};

const RUN_ID: &str = "classified-evidence-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

struct ProtectedExample {
    evidence_id: &'static str,
    classification: Classification,
    classification_label: &'static str,
    locator: &'static str,
    raw_value: &'static str,
    digest: &'static str,
}

const EXAMPLES: [ProtectedExample; 2] = [
    ProtectedExample {
        evidence_id: "ev-0007",
        classification: Classification::Secret,
        classification_label: "Secret",
        locator: ".env.example:3",
        raw_value: "fake-secret-value-for-redaction-test",
        digest: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    ProtectedExample {
        evidence_id: "ev-0008",
        classification: Classification::Sensitive,
        classification_label: "Sensitive",
        locator: "config/users.yaml:12",
        raw_value: "alice@example.test",
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
];

struct TempFixture {
    root: PathBuf,
}

impl TempFixture {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r07-protected-{}-{now}-{unique}",
            std::process::id()
        ));
        TempFixture { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("tmp").join("sovri-mat-98.db")
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn every_protected_classification_is_redacted_consistently() {
    let fixture = TempFixture::new();
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");

    // When the "classified-evidence-2026-06-24" corpus is written to SQLite.
    database
        .write_completed_corpus(&classified_corpus())
        .expect("the classified corpus write succeeds");

    for example in &EXAMPLES {
        let records = database
            .query_evidence("id", example.evidence_id)
            .expect("the classified evidence query succeeds");
        let record = records
            .first()
            .expect("the classified evidence record exists");

        // Then evidence "<evidence_id>" has classification "<classification>".
        assert_eq!(record.classification(), example.classification_label);
        // And evidence "<evidence_id>" has redaction status "redacted".
        assert_eq!(record.redaction_status(), "redacted");

        // And evidence "<evidence_id>" exposes only id, type, location, classification, collector metadata, and integrity digest.
        assert_eq!(record.id(), example.evidence_id);
        assert_eq!(record.locator(), example.locator);
        assert_eq!(record.digest(), example.digest);
        let exposed = format!("{record:?}");
        let allowed_fields = [
            "id",
            "kind",
            "locator",
            "classification",
            "collector_metadata",
            "digest",
        ];
        assert!(
            exposed_field_names(&exposed)
                .iter()
                .all(|field| allowed_fields.contains(field)),
            "the queried metadata for {} contains a field outside the protected allow-list: {exposed}",
            example.evidence_id
        );
        assert!(
            !exposed.contains(example.raw_value),
            "the queried metadata for {} must not expose its raw value",
            example.evidence_id
        );
    }
}

fn classified_corpus() -> Corpus {
    EXAMPLES.iter().fold(
        Corpus::new(EXECUTED_AT).with_run_id(RUN_ID),
        |corpus, example| corpus.with_stored_evidence(&classified_evidence(example)),
    )
}

fn classified_evidence(example: &ProtectedExample) -> Evidence {
    Evidence::builder()
        .id(example.evidence_id)
        .kind(EvidenceKind::Config)
        .locator(example.locator)
        .content_hash(example.digest)
        .excerpt(example.raw_value)
        .classification(example.classification)
        .build()
        .expect("the classified evidence validates")
}

fn exposed_field_names(debug: &str) -> Vec<&str> {
    debug
        .split_once('{')
        .map(|(_, fields)| fields.trim_end_matches('}'))
        .unwrap_or_default()
        .split(", ")
        .filter_map(|field| field.split_once(':').map(|(name, _)| name.trim()))
        .collect()
}

#[allow(dead_code)]
trait ProtectedEvidenceProjection {
    fn classification(&self) -> &str {
        panic!("LocalDatabaseEvidence::classification is not implemented")
    }

    fn redaction_status(&self) -> &str {
        panic!("LocalDatabaseEvidence::redaction_status is not implemented")
    }
}

impl ProtectedEvidenceProjection for LocalDatabaseEvidence {}
