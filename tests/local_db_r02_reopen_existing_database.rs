// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — reopening a current local `SQLite` database preserves existing
//! corpus rows. Covers issue #337.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::LocalDatabase;

const RUN_ID: &str = "shopfront-2026-06-24";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const EVIDENCE_ID: &str = "ev-0001";
const EVIDENCE_DIGEST: &str =
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
            "sovri-agent-test-{}-{now}-{unique}",
            std::process::id()
        ));
        TempDatabase {
            // Preserve the concrete scenario path inside an isolated root.
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

fn seed_current_corpus(path: &Path) {
    let connection = Connection::open(path).expect("the current database can be seeded");
    connection
        .execute("INSERT INTO scan_runs (id) VALUES (?1)", [RUN_ID])
        .expect("run can be seeded");
    connection
        .execute(
            "INSERT INTO frameworks (id, version) VALUES (?1, ?2)",
            params![FRAMEWORK_ID, FRAMEWORK_VERSION],
        )
        .expect("framework version can be seeded");
    connection
        .execute(
            "INSERT INTO evidence_metadata (id, digest) VALUES (?1, ?2)",
            params![EVIDENCE_ID, EVIDENCE_DIGEST],
        )
        .expect("evidence digest can be seeded");
}

fn create_database_with_schema_version(
    path: &Path,
    schema_version: u32,
    include_framework_version: bool,
    include_evidence_digest: bool,
) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("legacy database parent can be created");
    }
    let framework_version_column = if include_framework_version {
        ", version TEXT NOT NULL"
    } else {
        ""
    };
    let evidence_digest_column = if include_evidence_digest {
        ", digest TEXT NOT NULL"
    } else {
        ""
    };
    let schema = format!(
        "
        CREATE TABLE scan_runs (id TEXT PRIMARY KEY);
        CREATE TABLE frameworks (id TEXT PRIMARY KEY{framework_version_column});
        CREATE TABLE evidence_metadata (id TEXT PRIMARY KEY{evidence_digest_column});
        CREATE TABLE schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO schema_migrations(version, name)
        VALUES (1, '0001-initial');
        PRAGMA user_version = {schema_version};
        "
    );
    let connection = Connection::open(path).expect("legacy database can be created");
    connection
        .execute_batch(&schema)
        .expect("legacy version 1 database can be seeded");
}

fn run_exists(path: &Path, run_id: &str) -> bool {
    let connection = Connection::open(path).expect("the reopened database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM scan_runs WHERE id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .expect("scan run presence can be inspected");
    count == 1
}

fn framework_version(path: &Path, framework_id: &str) -> String {
    let connection = Connection::open(path).expect("the reopened database can be inspected");
    connection
        .query_row(
            "SELECT version FROM frameworks WHERE id = ?1",
            [framework_id],
            |row| row.get(0),
        )
        .expect("framework version can be inspected")
}

fn evidence_digest(path: &Path, evidence_id: &str) -> String {
    let connection = Connection::open(path).expect("the reopened database can be inspected");
    connection
        .query_row(
            "SELECT digest FROM evidence_metadata WHERE id = ?1",
            [evidence_id],
            |row| row.get(0),
        )
        .expect("evidence digest can be inspected")
}

#[test]
fn reopening_a_current_database_validates_the_schema_and_preserves_rows() {
    let database = TempDatabase::new();

    // Given the database schema version is 1.
    let created = LocalDatabase::open(database.path()).expect("the current database opens");
    assert_eq!(created.schema_version(), 1);
    drop(created);
    seed_current_corpus(database.path());

    // When the operator reopens the local database at "./tmp/sovri-mat-98.db".
    let reopened = LocalDatabase::open(database.path()).expect("the local database reopens");

    // Then the database exposes schema version 1.
    assert_eq!(reopened.schema_version(), 1);

    // And run "shopfront-2026-06-24" is still present.
    assert!(run_exists(database.path(), RUN_ID));

    // And framework "gdpr-eprivacy" still has version "2016-679".
    assert_eq!(
        framework_version(database.path(), FRAMEWORK_ID),
        FRAMEWORK_VERSION
    );

    // And evidence "ev-0001" still has digest
    // "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
    assert_eq!(
        evidence_digest(database.path(), EVIDENCE_ID),
        EVIDENCE_DIGEST
    );
}

#[test]
fn reopening_a_version_1_database_missing_required_columns_is_rejected() {
    let database = TempDatabase::new();
    create_database_with_schema_version(database.path(), 1, false, false);

    let Err(error) = LocalDatabase::open(database.path()) else {
        panic!("a version 1 database missing required columns should not open as current");
    };

    let error_message = error.to_string();
    assert!(
        error_message.contains("frameworks.version"),
        "schema validation should name the missing required column, got {error_message:?}"
    );
    assert!(
        error_message.contains("evidence_metadata.digest"),
        "schema validation should name every missing required column, got {error_message:?}"
    );
}

#[test]
fn reopening_a_version_1_database_missing_evidence_digest_is_rejected() {
    let database = TempDatabase::new();
    create_database_with_schema_version(database.path(), 1, true, false);

    let Err(error) = LocalDatabase::open(database.path()) else {
        panic!(
            "a version 1 database missing the evidence digest column should not open as current"
        );
    };

    let error_message = error.to_string();
    assert!(
        error_message.contains("evidence_metadata.digest"),
        "schema validation should name the missing evidence digest column, got {error_message:?}"
    );
    assert!(
        !error_message.contains("frameworks.version"),
        "schema validation should not name columns that are present, got {error_message:?}"
    );
}

#[test]
fn reopening_a_future_schema_version_is_rejected() {
    let database = TempDatabase::new();
    create_database_with_schema_version(database.path(), 2, true, true);

    let Err(error) = LocalDatabase::open(database.path()) else {
        panic!("a database from a future schema version should not open as current");
    };

    let error_message = error.to_string();
    assert!(
        error_message.contains("unsupported schema version 2"),
        "schema validation should reject future versions explicitly, got {error_message:?}"
    );
    assert!(
        !error_message.contains("missing required columns"),
        "a future-version failure should not be reported as a missing-column failure, got {error_message:?}"
    );
}
