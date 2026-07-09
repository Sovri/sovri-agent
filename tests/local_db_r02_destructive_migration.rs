// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — a packaged migration that would drop persisted corpus data is
//! rejected before data loss. Covers issue #339.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::{LocalDatabase, PackagedMigration};

const RUN_ID: &str = "shopfront-2026-06-24";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const EVIDENCE_ID: &str = "ev-0001";
const EVIDENCE_DIGEST: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] = &[PackagedMigration::new(
    2,
    "0002-drop-evidence-metadata",
    "DROP TABLE evidence_metadata;",
)];

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
            "sovri-agent-test-{}-{now}-{unique}",
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

fn create_version_1_database_with_single_run_and_evidence(path: &Path) {
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
            CREATE TABLE evidence_metadata (
              id TEXT PRIMARY KEY,
              digest TEXT NOT NULL
            );
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
    connection
        .execute("INSERT INTO scan_runs (id) VALUES (?1)", [RUN_ID])
        .expect("run can be seeded");
    connection
        .execute(
            "INSERT INTO frameworks (id, version) VALUES (?1, ?2)",
            params![FRAMEWORK_ID, FRAMEWORK_VERSION],
        )
        .expect("framework can be seeded");
    connection
        .execute(
            "INSERT INTO evidence_metadata (id, digest) VALUES (?1, ?2)",
            params![EVIDENCE_ID, EVIDENCE_DIGEST],
        )
        .expect("evidence can be seeded");
}

fn raw_schema_version(path: &Path) -> u32 {
    let connection = Connection::open(path).expect("database can be inspected");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version can be inspected");
    u32::try_from(version).expect("schema version is non-negative")
}

fn run_count(path: &Path) -> i64 {
    let connection = Connection::open(path).expect("database can be inspected");
    connection
        .query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row.get(0))
        .expect("run count can be inspected")
}

fn evidence_metadata_count(path: &Path) -> i64 {
    let connection = Connection::open(path).expect("database can be inspected");
    connection
        .query_row("SELECT COUNT(*) FROM evidence_metadata", [], |row| {
            row.get(0)
        })
        .expect("evidence metadata count can be inspected")
}

fn run_exists(path: &Path, run_id: &str) -> bool {
    let connection = Connection::open(path).expect("database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM scan_runs
             WHERE id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .expect("scan run can be inspected");
    count == 1
}

fn evidence_digest(path: &Path, evidence_id: &str) -> String {
    let connection = Connection::open(path).expect("database can be inspected");
    connection
        .query_row(
            "SELECT digest
             FROM evidence_metadata
             WHERE id = ?1",
            [evidence_id],
            |row| row.get(0),
        )
        .expect("evidence digest can be inspected")
}

#[test]
fn a_migration_that_would_drop_persisted_corpus_data_is_rejected() {
    let database = TempDatabase::new();

    // Given the database schema version is 1.
    create_version_1_database_with_single_run_and_evidence(database.path());
    assert_eq!(raw_schema_version(database.path()), 1);

    // And the database contains exactly 1 run row.
    assert_eq!(run_count(database.path()), 1);

    // And the database contains exactly 1 evidence metadata row.
    assert_eq!(evidence_metadata_count(database.path()), 1);

    // And packaged migration version 2 contains destructive operation
    // "DROP TABLE evidence_metadata".
    let Err(error) = LocalDatabase::open_with_packaged_migrations(
        database.path(),
        DESTRUCTIVE_PACKAGED_MIGRATIONS,
    ) else {
        panic!("destructive packaged migration version 2 should be rejected");
    };

    // Then packaged migration version 2 is rejected as destructive.
    let error_message = error.to_string();
    assert!(
        error_message.contains("destructive"),
        "the rejection should classify the migration as destructive, got {error_message:?}"
    );
    assert!(
        error_message.contains("0002-drop-evidence-metadata"),
        "the rejection should name the destructive migration, got {error_message:?}"
    );

    // And the database still exposes schema version 1.
    assert_eq!(raw_schema_version(database.path()), 1);

    // And run "shopfront-2026-06-24" is still present.
    assert!(run_exists(database.path(), RUN_ID));

    // And evidence "ev-0001" still has digest
    // "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
    assert_eq!(
        evidence_digest(database.path(), EVIDENCE_ID),
        EVIDENCE_DIGEST
    );

    // And the database still contains exactly 1 run row.
    assert_eq!(run_count(database.path()), 1);

    // And the database still contains exactly 1 evidence metadata row.
    assert_eq!(evidence_metadata_count(database.path()), 1);
}
