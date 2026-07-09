// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 -- export reconstruction stops on a digest mismatch. Covers issue #357.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "classified-evidence-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const EVIDENCE_ID: &str = "ev-0007";
const EVIDENCE_LOCATOR: &str = ".env.example:3";
const EXPECTED_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ACTUAL_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
            "sovri-agent-mat98-r06-reconstruct-{}-{now}-{unique}",
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
fn export_reconstruction_stops_on_a_digest_mismatch() {
    let fixture = TempFixture::new();

    // Given an open local database with Secret evidence linked to the expected digest.
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    database
        .write_completed_corpus(&classified_corpus())
        .expect("the classified corpus write succeeds");

    // Given the store resolves "ev-0007" to the mismatched actual digest.
    let store = mismatched_store(&fixture.store_path());

    // When the operator reconstructs the classified corpus from SQLite.
    let reconstruction = database.validate_corpus_reconstruction(&store, RUN_ID);

    // Then reconstruction fails with the linked-evidence integrity error.
    let error = reconstruction
        .as_ref()
        .expect_err("the mismatched corpus cannot be reconstructed");
    assert!(error.is_integrity_error());
    assert_eq!(error.expected_digest(), Some(EXPECTED_DIGEST));
    assert_eq!(error.actual_digest(), Some(ACTUAL_DIGEST));

    // And no export format receives a reconstructed corpus from mismatched evidence.
    for format in ["PDF", "SpreadsheetML", "signed JSON"] {
        assert!(
            reconstruction.as_ref().ok().is_none(),
            "{format} must not receive an exportable corpus"
        );
    }
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

fn mismatched_store(path: &Path) -> EvidenceStore {
    let evidence = Evidence::builder()
        .id(EVIDENCE_ID)
        .kind(EvidenceKind::Config)
        .locator(EVIDENCE_LOCATOR)
        .content(Vec::<u8>::new())
        .classification(sovri_sdk::Classification::Secret)
        .build()
        .expect("the classified evidence validates");
    assert_eq!(evidence.content_hash(), ACTUAL_DIGEST);

    let mut store = EvidenceStore::open(path).expect("the content-addressed store opens");
    store
        .write(&evidence)
        .expect("the mismatched evidence is persisted");
    store
}
