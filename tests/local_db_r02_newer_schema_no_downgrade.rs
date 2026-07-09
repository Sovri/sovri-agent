// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 — a database newer than the packaged agent is rejected without applying
//! older packaged migrations. Covers issue #340.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::{LocalDatabase, PackagedMigration};

const RUN_ID: &str = "shopfront-2026-06-24";
const EVIDENCE_ID: &str = "ev-0001";
const PACKAGED_AGENT_CURRENT_SCHEMA_VERSION: u32 = 2;

const PACKAGED_AGENT_SCHEMA_2_MIGRATIONS: &[PackagedMigration] = &[
    PackagedMigration::new(
        1,
        "0001-packaged-agent-marker",
        "CREATE TABLE packaged_agent_v1_marker (id TEXT PRIMARY KEY);",
    ),
    PackagedMigration::new(
        PACKAGED_AGENT_CURRENT_SCHEMA_VERSION,
        "0002-packaged-agent-marker",
        "CREATE TABLE packaged_agent_v2_marker (id TEXT PRIMARY KEY);",
    ),
];

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

fn create_version_3_database_with_single_run_and_evidence(path: &Path) {
    fs::create_dir_all(path.parent().expect("database path has a parent"))
        .expect("database parent can be created");
    let connection = Connection::open(path).expect("version 3 database can be created");
    connection
        .execute_batch(
            "
            CREATE TABLE scan_runs (id TEXT PRIMARY KEY);
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
            VALUES (3, '0003-future-agent-schema');
            PRAGMA user_version = 3;
            ",
        )
        .expect("version 3 schema can be seeded");
    connection
        .execute("INSERT INTO scan_runs (id) VALUES (?1)", [RUN_ID])
        .expect("run can be seeded");
    connection
        .execute(
            "INSERT INTO evidence_metadata (id, digest) VALUES (?1, ?2)",
            params![EVIDENCE_ID, "sha256:future-schema"],
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

fn applied_migration_versions(path: &Path) -> Vec<u32> {
    let connection = Connection::open(path).expect("database can be inspected");
    let mut statement = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .expect("migration ledger can be inspected");
    let rows = statement
        .query_map([], |row| row.get::<_, u32>(0))
        .expect("migration rows can be read");
    rows.collect::<Result<Vec<_>, _>>()
        .expect("migration versions can be decoded")
}

fn table_exists(path: &Path, table_name: &str) -> bool {
    let connection = Connection::open(path).expect("database can be inspected");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE type = 'table' AND name = ?1",
            [table_name],
            |row| row.get(0),
        )
        .expect("schema table can be inspected");
    count == 1
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

#[test]
fn a_database_newer_than_the_packaged_agent_is_not_downgraded() {
    let database = TempDatabase::new();

    // Given the database schema version is 3.
    create_version_3_database_with_single_run_and_evidence(database.path());
    assert_eq!(raw_schema_version(database.path()), 3);

    // And the packaged agent's current schema version is 2.
    let packaged_database = TempDatabase::new();
    let opened_packaged_database = LocalDatabase::open_with_packaged_migrations(
        packaged_database.path(),
        PACKAGED_AGENT_SCHEMA_2_MIGRATIONS,
    )
    .expect("the packaged agent test migrations open");
    assert_eq!(
        opened_packaged_database.schema_version(),
        PACKAGED_AGENT_CURRENT_SCHEMA_VERSION
    );

    // When the operator reopens the local database at "./tmp/sovri-mat-98.db".
    let Err(error) = LocalDatabase::open_with_packaged_migrations(
        database.path(),
        PACKAGED_AGENT_SCHEMA_2_MIGRATIONS,
    ) else {
        panic!("a database newer than the packaged agent should not open or downgrade");
    };

    // Then the open fails with an unsupported newer schema error.
    let error_message = error.to_string();
    assert!(
        error_message.contains("unsupported newer schema"),
        "the failure should classify the schema as newer than the packaged agent, got {error_message:?}"
    );
    assert!(
        error_message.contains("version 3") && error_message.contains("version is 2"),
        "the failure should name database version 3 and packaged version 2, got {error_message:?}"
    );

    // And no migration is applied.
    assert_eq!(raw_schema_version(database.path()), 3);
    assert_eq!(applied_migration_versions(database.path()), vec![3]);
    assert!(!table_exists(database.path(), "packaged_agent_v1_marker"));
    assert!(!table_exists(database.path(), "packaged_agent_v2_marker"));

    // And the database still contains exactly 1 run row.
    assert_eq!(run_count(database.path()), 1);

    // And the database still contains exactly 1 evidence metadata row.
    assert_eq!(evidence_metadata_count(database.path()), 1);

    // And run "shopfront-2026-06-24" remains unchanged.
    assert!(run_exists(database.path(), RUN_ID));
}
