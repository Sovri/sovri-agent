// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 -- matching linked evidence digests are readable. Covers issue #355.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::{LocalDatabase, LocalDatabaseError, LocalDatabaseEvidence};
use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{Evidence, EvidenceKind, EvidenceStore};

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
            "sovri-agent-mat98-r06-matching-{}-{now}-{unique}",
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

#[allow(dead_code)]
trait LocalDatabaseLinkedEvidenceRead {
    fn read_linked_evidence(
        &self,
        _store: &EvidenceStore,
        _evidence_id: &str,
    ) -> Result<Option<LocalDatabaseEvidence>, LocalDatabaseError> {
        panic!("LocalDatabase::read_linked_evidence is not implemented")
    }
}

impl LocalDatabaseLinkedEvidenceRead for LocalDatabase {}

#[allow(dead_code)]
trait LocalDatabaseEvidenceDigest {
    fn digest(&self) -> &str {
        panic!("LocalDatabaseEvidence::digest is not implemented")
    }
}

impl LocalDatabaseEvidenceDigest for LocalDatabaseEvidence {}

#[test]
fn a_matching_digest_allows_the_linked_evidence_metadata_to_be_read() {
    let fixture = TempFixture::new();

    // Given an open local database at "./tmp/sovri-mat-98.db".
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");

    // And evidence "ev-0007" is linked with the expected digest and classified as Secret.
    database
        .write_completed_corpus(&classified_corpus())
        .expect("the classified corpus write succeeds");

    // Given the content-addressed store resolves "ev-0007" to the matching digest.
    let store = matching_store(&fixture.store_path());

    // When the operator reads linked evidence "ev-0007".
    let read = database.read_linked_evidence(&store, EVIDENCE_ID);

    // Then evidence metadata for "ev-0007" is returned.
    let metadata = read
        .as_ref()
        .expect("no integrity error is reported")
        .as_ref()
        .expect("linked evidence metadata is returned");
    assert_eq!(metadata.id(), EVIDENCE_ID);

    // And the returned digest is the expected digest.
    assert_eq!(metadata.digest(), EXPECTED_DIGEST);

    // And no integrity error is reported.
    assert!(read.is_ok());
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

fn matching_store(path: &Path) -> EvidenceStore {
    let evidence = Evidence::builder()
        .id(EVIDENCE_ID)
        .kind(EvidenceKind::Config)
        .locator(EVIDENCE_LOCATOR)
        .content(b"abc".to_vec())
        .classification(sovri_sdk::Classification::Secret)
        .build()
        .expect("the classified evidence validates");
    assert_eq!(evidence.content_hash(), EXPECTED_DIGEST);

    let mut store = EvidenceStore::open(path).expect("the content-addressed store opens");
    store
        .write(&evidence)
        .expect("the matching evidence is persisted");
    store
}
