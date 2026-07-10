// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 -- classified evidence persists only allowed metadata. Covers issue #359.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::{Classification, Corpus};

const RUN_ID: &str = "classified-evidence-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const SECRET_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SENSITIVE_DIGEST: &str =
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
            "sovri-agent-mat98-r07-metadata-{}-{now}-{unique}",
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
fn secret_and_sensitive_records_are_stored_as_metadata_and_digests_only() {
    let fixture = TempFixture::new();
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");

    // When the "classified-evidence-2026-06-24" corpus is written to SQLite.
    database
        .write_completed_corpus(&classified_corpus())
        .expect("the classified corpus write succeeds");
    drop(database);

    let connection =
        Connection::open(fixture.database_path()).expect("the SQLite database can be inspected");
    let secret = evidence_metadata(&connection, "ev-0007");
    let sensitive = evidence_metadata(&connection, "ev-0008");

    // Then evidence "ev-0007" stores classification "Secret".
    assert_eq!(secret.classification, "Secret");
    // And evidence "ev-0007" stores locator ".env.example:3".
    assert_eq!(secret.locator, ".env.example:3");
    // And evidence "ev-0007" stores digest "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
    assert_eq!(secret.digest, SECRET_DIGEST);

    // And evidence "ev-0008" stores classification "Sensitive".
    assert_eq!(sensitive.classification, "Sensitive");
    // And evidence "ev-0008" stores locator "config/users.yaml:12".
    assert_eq!(sensitive.locator, "config/users.yaml:12");
    // And evidence "ev-0008" stores digest "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".
    assert_eq!(sensitive.digest, SENSITIVE_DIGEST);
}

struct PersistedEvidence {
    classification: String,
    locator: String,
    digest: String,
}

fn evidence_metadata(connection: &Connection, evidence_id: &str) -> PersistedEvidence {
    connection
        .query_row(
            "SELECT classification, locator, digest
             FROM evidence_metadata
             WHERE id = ?1",
            params![evidence_id],
            |row| {
                Ok(PersistedEvidence {
                    classification: row.get(0)?,
                    locator: row.get(1)?,
                    digest: row.get(2)?,
                })
            },
        )
        .expect("the classified evidence metadata can be read")
}

fn classified_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_classified_evidence(
            "ev-0007",
            "config",
            ".env.example:3",
            Classification::Secret,
            SECRET_DIGEST,
        )
        .with_classified_evidence(
            "ev-0008",
            "config",
            "config/users.yaml:12",
            Classification::Sensitive,
            SENSITIVE_DIGEST,
        )
}
