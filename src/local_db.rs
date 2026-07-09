// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Local `SQLite` database for the air-gapped compliance corpus.
//!
//! The database is a queryable local index over the persisted scan corpus. The
//! MAT-94 content-addressed evidence store remains the backing store for
//! evidence bytes; this module stores only local `SQLite` rows and integrity
//! metadata.

use std::error::Error;
use std::fmt::{self, Write as _};
use std::fs;
use std::path::Path;

use rusqlite::Connection;

/// The schema version created by the first packaged migration.
pub const INITIAL_SCHEMA_VERSION: u32 = 1;

const REQUIRED_SCHEMA_TABLES: &[&str] = &[
    "scan_runs",
    "frameworks",
    "controls",
    "control_results",
    "compliance_gaps",
    "evidence_metadata",
    "score_summaries",
    "exports",
];

/// A local `SQLite` database opened by `sovri-agent`.
pub struct LocalDatabase {
    connection: Connection,
}

impl LocalDatabase {
    /// Opens or creates a local `SQLite` database and applies packaged migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, `SQLite` cannot
    /// open the file, or the packaged initial schema cannot be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LocalDatabaseError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(LocalDatabaseError::Io)?;
        }
        let connection = Connection::open(path).map_err(LocalDatabaseError::Sqlite)?;
        apply_initial_schema(&connection)?;
        Ok(LocalDatabase { connection })
    }

    /// Returns the database schema version exposed by `SQLite`.
    ///
    /// # Panics
    ///
    /// Panics only if an opened `SQLite` connection cannot read its
    /// `user_version` pragma or reports a negative version.
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        let version = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("an open SQLite connection exposes PRAGMA user_version");
        u32::try_from(version).expect("SQLite schema version is non-negative")
    }

    /// Lists the application schema tables currently present in stable order.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read `sqlite_schema`.
    pub fn schema_tables(&self) -> Result<Vec<String>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT name
                 FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Lists packaged migrations applied to this database in version order.
    ///
    /// # Errors
    ///
    /// Returns `Ok(Vec::new())` when the migration ledger table exists but has
    /// no rows.
    ///
    /// Returns an error if `SQLite` cannot prepare or run the migration-ledger
    /// query, including when the `schema_migrations` table is missing, the
    /// expected `version` / `name` columns are missing or unreadable, or a row's
    /// migration name cannot be decoded as text.
    pub fn applied_migrations(&self) -> Result<Vec<String>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM schema_migrations ORDER BY version")
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }
}

fn apply_initial_schema(connection: &Connection) -> Result<(), LocalDatabaseError> {
    connection
        .execute_batch(&initial_schema_sql())
        .map_err(LocalDatabaseError::Sqlite)
}

fn initial_schema_sql() -> String {
    let mut sql = String::from(
        "BEGIN;
         CREATE TABLE IF NOT EXISTS schema_migrations (
           version INTEGER PRIMARY KEY,
           name TEXT NOT NULL,
           applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         INSERT OR IGNORE INTO schema_migrations(version, name)
           VALUES (1, '0001-initial');
         PRAGMA user_version = 1;",
    );
    for table in REQUIRED_SCHEMA_TABLES {
        write!(
            sql,
            "CREATE TABLE IF NOT EXISTS {table} (
               id TEXT PRIMARY KEY
             );",
        )
        .expect("writing SQL to a String cannot fail");
    }
    sql.push_str("COMMIT;");
    sql
}

/// Errors returned by local database operations.
#[derive(Debug)]
pub enum LocalDatabaseError {
    /// Filesystem setup failed before `SQLite` opened the database.
    Io(std::io::Error),
    /// `SQLite` failed while opening, migrating, or reading the database.
    Sqlite(rusqlite::Error),
}

impl fmt::Display for LocalDatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalDatabaseError::Io(error) => {
                write!(formatter, "local database filesystem error: {error}")
            }
            LocalDatabaseError::Sqlite(error) => {
                write!(formatter, "local database sqlite error: {error}")
            }
        }
    }
}

impl Error for LocalDatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LocalDatabaseError::Io(error) => Some(error),
            LocalDatabaseError::Sqlite(error) => Some(error),
        }
    }
}
