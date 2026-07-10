// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 -- missing linked evidence fails integrity checks. Covers issue #358.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, LocalDatabaseError};
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::EvidenceStore;

const RUN_ID: &str = "classified-evidence-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const EVIDENCE_ID: &str = "ev-0007";
const EVIDENCE_LOCATOR: &str = ".env.example:3";
const EXPECTED_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

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
            "sovri-agent-mat98-r06-missing-{}-{now}-{unique}",
            std::process::id()
        ));
        TempFixture { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("tmp").join("sovri-mat-98.db")
    }

    fn store_path(&self) -> PathBuf {
        self.root.join("evidence-store")
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_missing_linked_evidence_record_is_reported_as_an_integrity_error() {
    let fixture = TempFixture::new();
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    database
        .write_completed_corpus(&classified_corpus())
        .expect("the linked evidence metadata is persisted");

    // Given the content-addressed store has no record for evidence "ev-0007".
    let store = EvidenceStore::open(fixture.store_path()).expect("the empty store opens");

    // When the operator reads linked evidence "ev-0007".
    let read = database.read_linked_evidence(&store, EVIDENCE_ID);

    // Then the read fails with an integrity error.
    let error = read
        .as_ref()
        .expect_err("missing evidence must fail its integrity check");
    assert!(error.is_integrity_error());
    assert!(matches!(error, LocalDatabaseError::MissingEvidence { .. }));

    // And the error reports missing evidence id "ev-0007".
    assert!(error.to_string().contains(EVIDENCE_ID));

    // And the error reports expected digest "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
    assert_eq!(error.expected_digest(), Some(EXPECTED_DIGEST));

    // And no linked evidence value is trusted.
    assert!(read.is_err());
}

fn classified_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_classified_evidence(
            EVIDENCE_ID,
            "config",
            EVIDENCE_LOCATOR,
            Classification::Secret,
            EXPECTED_DIGEST,
        )
}
