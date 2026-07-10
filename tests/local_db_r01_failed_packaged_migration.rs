// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — a failed packaged migration rolls back its partial writes. Covers
//! issue #335.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use rusqlite::Connection;
use sovri_agent::local_db::{LocalDatabase, PackagedMigration};

const CORPUS_TABLES: &[&str] = &[
    "scan_runs",
    "frameworks",
    "controls",
    "control_results",
    "compliance_gaps",
    "evidence_metadata",
    "score_summaries",
    "exports",
];

const INITIAL_SCHEMA_SQL: &str = "
    CREATE TABLE scan_runs (id TEXT PRIMARY KEY);
    CREATE TABLE frameworks (id TEXT PRIMARY KEY);
    CREATE TABLE controls (id TEXT PRIMARY KEY);
    CREATE TABLE control_results (id TEXT PRIMARY KEY);
    CREATE TABLE compliance_gaps (id TEXT PRIMARY KEY);
    CREATE TABLE evidence_metadata (id TEXT PRIMARY KEY);
    CREATE TABLE score_summaries (id TEXT PRIMARY KEY);
    CREATE TABLE exports (id TEXT PRIMARY KEY);
";

const BROKEN_MIGRATION_SQL: &str = "
    CREATE TABLE partial_migration_marker (id TEXT PRIMARY KEY);
    INSERT INTO scan_runs (id) VALUES ('partial-scan-run');
    INSERT INTO frameworks (id) VALUES ('partial-framework');
    INSERT INTO controls (id) VALUES ('partial-control');
    INSERT INTO control_results (id) VALUES ('partial-result');
    INSERT INTO compliance_gaps (id) VALUES ('partial-gap');
    INSERT INTO evidence_metadata (id) VALUES ('partial-evidence');
    INSERT INTO score_summaries (id) VALUES ('partial-score');
    INSERT INTO exports (id) VALUES ('partial-export');
    INSERT INTO missing_table_for_rollback_check (id) VALUES ('boom');
";

const BROKEN_PACKAGED_MIGRATIONS: &[PackagedMigration] = &[
    PackagedMigration::new(1, "0001-initial", INITIAL_SCHEMA_SQL),
    PackagedMigration::new(2, "0002-broken", BROKEN_MIGRATION_SQL),
];

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r01-broken-migration-{}-{unique}",
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

fn schema_version(connection: &Connection) -> i64 {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version can be read after a failed migration")
}

fn table_exists(connection: &Connection, table_name: &str) -> bool {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE type = 'table' AND name = ?1",
            [table_name],
            |row| row.get(0),
        )
        .expect("schema can be inspected after a failed migration");
    count == 1
}

fn committed_rows(connection: &Connection, table_name: &str) -> i64 {
    if !table_exists(connection, table_name) {
        return 0;
    }

    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
            row.get(0)
        })
        .expect("corpus row count can be inspected after a failed migration")
}

fn applied_migration_exists(connection: &Connection, migration_name: &str) -> bool {
    if !table_exists(connection, "schema_migrations") {
        return false;
    }

    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM schema_migrations
             WHERE name = ?1",
            [migration_name],
            |row| row.get(0),
        )
        .expect("migration ledger can be inspected after a failed migration");
    count == 1
}

#[test]
fn a_failed_packaged_migration_is_rolled_back() {
    // Given the packaged agent contains migration "0001-initial".
    // And the packaged agent contains migration "0002-broken" that fails after
    // creating table "partial_migration_marker".
    let database = TempDatabase::new();

    // When the operator opens the local database at "./tmp/sovri-mat-98.db".
    let Err(error) =
        LocalDatabase::open_with_packaged_migrations(database.path(), BROKEN_PACKAGED_MIGRATIONS)
    else {
        panic!("opening with a broken packaged migration should fail");
    };

    // Then the open fails with a migration error for "0002-broken".
    let error_message = error.to_string();
    assert!(
        error_message.contains("0002-broken"),
        "expected the error to name the broken migration, got {error_message:?}"
    );

    let connection =
        Connection::open(database.path()).expect("the failed database can be inspected");

    // And the database does not expose schema version 2.
    assert_ne!(schema_version(&connection), 2);
    assert!(
        !applied_migration_exists(&connection, "0002-broken"),
        "the failed migration was recorded in schema_migrations"
    );

    // And table "partial_migration_marker" does not exist.
    assert!(
        !table_exists(&connection, "partial_migration_marker"),
        "the broken migration's marker table was rolled back"
    );

    // And no scan run, framework, control, result, gap, evidence metadata,
    // score summary, or export record is committed.
    for table in CORPUS_TABLES {
        assert_eq!(
            committed_rows(&connection, table),
            0,
            "partial rows in {table} were committed despite migration rollback"
        );
    }
}
