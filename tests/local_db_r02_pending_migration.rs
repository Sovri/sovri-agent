// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — reopening applies a pending packaged migration without losing
//! existing corpus data. Covers issue #338.

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

fn create_version_1_database_with_run_evidence_link(path: &Path) {
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
              run_id TEXT NOT NULL,
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
            "INSERT INTO evidence_metadata (id, run_id, digest) VALUES (?1, ?2, ?3)",
            params![EVIDENCE_ID, RUN_ID, EVIDENCE_DIGEST],
        )
        .expect("linked evidence can be seeded");
}

fn raw_schema_version(path: &Path) -> u32 {
    let connection = Connection::open(path).expect("database can be inspected");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version can be inspected");
    u32::try_from(version).expect("schema version is non-negative")
}

fn migration_version_applied(path: &Path, version: u32) -> bool {
    let connection = Connection::open(path).expect("database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM schema_migrations
             WHERE version = ?1",
            [i64::from(version)],
            |row| row.get(0),
        )
        .expect("migration ledger can be inspected");
    count == 1
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

fn evidence_is_linked_to_run(path: &Path, evidence_id: &str, run_id: &str) -> bool {
    let connection = Connection::open(path).expect("database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM evidence_metadata
             WHERE id = ?1 AND run_id = ?2",
            params![evidence_id, run_id],
            |row| row.get(0),
        )
        .expect("evidence link can be inspected");
    count == 1
}

#[test]
fn reopening_applies_a_pending_packaged_migration_without_losing_data() {
    let database = TempDatabase::new();

    // Given the database is at schema version 1.
    create_version_1_database_with_run_evidence_link(database.path());
    assert_eq!(raw_schema_version(database.path()), 1);

    // And packaged migration version 2 is pending.
    assert!(!migration_version_applied(database.path(), 2));

    // When the operator reopens the local database at "./tmp/sovri-mat-98.db".
    let reopened = LocalDatabase::open(database.path()).expect("the local database reopens");

    // Then packaged migration version 2 is applied.
    assert!(migration_version_applied(database.path(), 2));

    // And the database exposes schema version 2.
    assert_eq!(reopened.schema_version(), 2);

    // And run "shopfront-2026-06-24" is still present.
    assert!(run_exists(database.path(), RUN_ID));

    // And evidence "ev-0001" is still linked to run "shopfront-2026-06-24".
    assert!(evidence_is_linked_to_run(
        database.path(),
        EVIDENCE_ID,
        RUN_ID
    ));
}
