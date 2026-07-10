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

const OBFUSCATED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] = &[PackagedMigration::new(
    2,
    "0002-commented-drop-evidence-metadata",
    "DROP/* destructive */ TABLE \"evidence_metadata\";",
)];

const STRING_LITERAL_MARKER_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-string-marker-drop-evidence-metadata",
        "
        CREATE TABLE notes (body TEXT);
        INSERT INTO notes(body) VALUES ('-- marker');
        DROP TABLE evidence_metadata;
        ",
    )];

const QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] = &[PackagedMigration::new(
    2,
    "0002-qualified-drop-evidence-metadata",
    r#"DROP TABLE "main"."evidence_metadata";"#,
)];

const UNQUOTED_SCHEMA_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-unquoted-schema-qualified-drop-evidence-metadata",
        r#"DROP TABLE main."evidence_metadata";"#,
    )];

const BACKTICK_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-backtick-qualified-drop-evidence-metadata",
        "DROP TABLE `main`.`evidence_metadata`;",
    )];

const BRACKET_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-bracket-qualified-drop-evidence-metadata",
        "DROP TABLE [main].[evidence_metadata];",
    )];

const DOT_NAMED_AUXILIARY_TABLE_MIGRATIONS: &[PackagedMigration] = &[PackagedMigration::new(
    2,
    "0002-drop-dot-named-auxiliary-table",
    r#"DROP TABLE "archive.evidence_metadata";"#,
)];

const SINGLE_QUOTED_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-single-quoted-drop-evidence-metadata",
        "DROP TABLE 'evidence_metadata';",
    )];

const DROP_COLUMN_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-drop-evidence-digest",
        "ALTER TABLE evidence_metadata DROP COLUMN digest;",
    )];

const DROP_COLUMN_WITHOUT_KEYWORD_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-drop-evidence-digest-without-column-keyword",
        "ALTER TABLE evidence_metadata DROP digest;",
    )];

const SQLITE_BLOCK_COMMENT_DESTRUCTIVE_PACKAGED_MIGRATIONS: &[PackagedMigration] =
    &[PackagedMigration::new(
        2,
        "0002-sqlite-comment-drop-evidence-metadata",
        "/* note /* nested */ DROP TABLE evidence_metadata; -- */",
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

fn destructive_migration_rejection(path: &Path, migrations: &[PackagedMigration]) -> String {
    let Err(error) = LocalDatabase::open_with_packaged_migrations(path, migrations) else {
        panic!("destructive packaged migration version 2 should be rejected");
    };

    error.to_string()
}

fn assert_rejected_as_destructive(error_message: &str, migration_name: &str) {
    assert!(
        error_message.contains("destructive"),
        "the rejection should classify the migration as destructive, got {error_message:?}"
    );
    assert!(
        error_message.contains(migration_name),
        "the rejection should name the destructive migration, got {error_message:?}"
    );
}

fn assert_single_run_and_evidence_preserved(path: &Path) {
    assert_eq!(raw_schema_version(path), 1);
    assert!(run_exists(path, RUN_ID));
    assert_eq!(evidence_digest(path, EVIDENCE_ID), EVIDENCE_DIGEST);
    assert_eq!(run_count(path), 1);
    assert_eq!(evidence_metadata_count(path), 1);
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
    let error_message =
        destructive_migration_rejection(database.path(), DESTRUCTIVE_PACKAGED_MIGRATIONS);

    // Then packaged migration version 2 is rejected as destructive.
    assert_rejected_as_destructive(&error_message, "0002-drop-evidence-metadata");

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

#[test]
fn a_comment_obfuscated_destructive_migration_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        OBFUSCATED_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(&error_message, "0002-commented-drop-evidence-metadata");
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn a_string_literal_comment_marker_does_not_hide_a_destructive_migration() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        STRING_LITERAL_MARKER_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(&error_message, "0002-string-marker-drop-evidence-metadata");
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn a_qualified_persisted_table_drop_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message =
        destructive_migration_rejection(database.path(), QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS);
    assert_rejected_as_destructive(&error_message, "0002-qualified-drop-evidence-metadata");
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn an_unquoted_schema_before_a_quoted_persisted_table_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        UNQUOTED_SCHEMA_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(
        &error_message,
        "0002-unquoted-schema-qualified-drop-evidence-metadata",
    );
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn alternate_quoted_qualified_persisted_table_drops_are_rejected() {
    for (migration_name, migrations) in [
        (
            "0002-backtick-qualified-drop-evidence-metadata",
            BACKTICK_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS,
        ),
        (
            "0002-bracket-qualified-drop-evidence-metadata",
            BRACKET_QUALIFIED_DESTRUCTIVE_PACKAGED_MIGRATIONS,
        ),
    ] {
        let database = TempDatabase::new();
        create_version_1_database_with_single_run_and_evidence(database.path());

        let error_message = destructive_migration_rejection(database.path(), migrations);
        assert_rejected_as_destructive(&error_message, migration_name);
        assert_single_run_and_evidence_preserved(database.path());
    }
}

#[test]
fn a_dot_inside_a_quoted_auxiliary_table_name_is_not_a_schema_qualifier() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());
    Connection::open(database.path())
        .expect("open database to create auxiliary table")
        .execute(
            r#"CREATE TABLE "archive.evidence_metadata" (value TEXT)"#,
            [],
        )
        .expect("create dot-named auxiliary table");

    let opened = LocalDatabase::open_with_packaged_migrations(
        database.path(),
        DOT_NAMED_AUXILIARY_TABLE_MIGRATIONS,
    )
    .expect("a dot inside a quoted identifier is not a schema qualification");

    assert_eq!(opened.schema_version(), 2);
    assert!(run_exists(database.path(), RUN_ID));
    assert_eq!(
        evidence_digest(database.path(), EVIDENCE_ID),
        EVIDENCE_DIGEST
    );
    assert_eq!(run_count(database.path()), 1);
    assert_eq!(evidence_metadata_count(database.path()), 1);
}

#[test]
fn a_single_quoted_persisted_table_drop_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        SINGLE_QUOTED_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(&error_message, "0002-single-quoted-drop-evidence-metadata");
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn dropping_a_column_from_a_persisted_table_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        DROP_COLUMN_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(&error_message, "0002-drop-evidence-digest");
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn dropping_a_column_without_the_column_keyword_is_rejected() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        DROP_COLUMN_WITHOUT_KEYWORD_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(
        &error_message,
        "0002-drop-evidence-digest-without-column-keyword",
    );
    assert_single_run_and_evidence_preserved(database.path());
}

#[test]
fn sqlite_non_nesting_block_comments_do_not_hide_a_destructive_migration() {
    let database = TempDatabase::new();
    create_version_1_database_with_single_run_and_evidence(database.path());

    let error_message = destructive_migration_rejection(
        database.path(),
        SQLITE_BLOCK_COMMENT_DESTRUCTIVE_PACKAGED_MIGRATIONS,
    );
    assert_rejected_as_destructive(&error_message, "0002-sqlite-comment-drop-evidence-metadata");
    assert_single_run_and_evidence_preserved(database.path());
}
