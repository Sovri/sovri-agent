// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 -- raw classified values never enter `SQLite`. Covers issue #360.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::{Classification, Corpus};

const RUN_ID: &str = "classified-evidence-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const SECRET_RAW_VALUE: &str = "fake-secret-value-for-redaction-test";
const SENSITIVE_RAW_VALUE: &str = "alice@example.test";
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
            "sovri-agent-mat98-r07-no-raw-{}-{now}-{unique}",
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
fn raw_classified_values_cannot_be_found_in_sqlite() {
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
    let stored_values = all_application_table_values(&connection);

    // Then no SQLite table contains "fake-secret-value-for-redaction-test".
    assert!(!contains_value(&stored_values, SECRET_RAW_VALUE));
    // And no SQLite table contains "alice@example.test".
    assert!(!contains_value(&stored_values, SENSITIVE_RAW_VALUE));

    // And no evidence row exposes a raw excerpt for "ev-0007".
    assert!(!contains_value(
        &evidence_row_values(&connection, "ev-0007"),
        SECRET_RAW_VALUE,
    ));
    // And no evidence row exposes a raw excerpt for "ev-0008".
    assert!(!contains_value(
        &evidence_row_values(&connection, "ev-0008"),
        SENSITIVE_RAW_VALUE,
    ));
}

fn all_application_table_values(connection: &Connection) -> Vec<String> {
    let mut table_statement = connection
        .prepare(
            "SELECT name
             FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .expect("the application tables can be listed");
    let tables = table_statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("the table list can be read")
        .collect::<Result<Vec<_>, _>>()
        .expect("every table name is valid");

    let mut values = Vec::new();
    for table in tables {
        let quoted_table = quote_identifier(&table);
        let mut column_statement = connection
            .prepare(&format!("PRAGMA table_info({quoted_table})"))
            .expect("the table columns can be listed");
        let columns = column_statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("the column list can be read")
            .collect::<Result<Vec<_>, _>>()
            .expect("every column name is valid");

        for column in columns {
            let quoted_column = quote_identifier(&column);
            let sql = format!(
                "SELECT CAST({quoted_column} AS TEXT)
                 FROM {quoted_table}
                 WHERE {quoted_column} IS NOT NULL"
            );
            let mut value_statement = connection
                .prepare(&sql)
                .expect("the table values can be selected");
            values.extend(
                value_statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .expect("the table values can be read")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("every persisted value can be inspected"),
            );
        }
    }
    values
}

fn evidence_row_values(connection: &Connection, evidence_id: &str) -> Vec<String> {
    connection
        .query_row(
            "SELECT id, digest, locator, classification
             FROM evidence_metadata
             WHERE id = ?1",
            params![evidence_id],
            |row| Ok(vec![row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
        )
        .expect("the evidence row can be inspected")
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn contains_value(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value.contains(needle))
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
