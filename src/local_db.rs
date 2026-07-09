// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Local `SQLite` database for the air-gapped compliance corpus.
//!
//! The database is a queryable local index over the persisted scan corpus. The
//! MAT-94 content-addressed evidence store remains the backing store for
//! evidence bytes; this module stores only local `SQLite` rows and integrity
//! metadata.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};

/// The schema version created by the first packaged migration.
pub const INITIAL_SCHEMA_VERSION: u32 = 1;

const PACKAGED_MIGRATIONS: &[PackagedMigration] = &[PackagedMigration::new(
    INITIAL_SCHEMA_VERSION,
    "0001-initial",
    INITIAL_SCHEMA_SQL,
)];

const INITIAL_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS frameworks (
      id TEXT PRIMARY KEY,
      version TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS controls (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS control_results (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS compliance_gaps (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS evidence_metadata (
      id TEXT PRIMARY KEY,
      digest TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS score_summaries (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS exports (id TEXT PRIMARY KEY);
";

const MIGRATION_LEDGER_SQL: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
";

const SCHEMA_VERSION_1_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
];

#[derive(Clone, Copy, Debug)]
struct RequiredSchemaColumn {
    table_name: &'static str,
    column_name: &'static str,
}

impl RequiredSchemaColumn {
    const fn new(table_name: &'static str, column_name: &'static str) -> Self {
        RequiredSchemaColumn {
            table_name,
            column_name,
        }
    }
}

/// A packaged `SQLite` migration embedded in the agent binary.
#[derive(Clone, Copy, Debug)]
pub struct PackagedMigration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

impl PackagedMigration {
    /// Creates a packaged migration descriptor.
    #[must_use]
    pub const fn new(version: u32, name: &'static str, sql: &'static str) -> Self {
        PackagedMigration { version, name, sql }
    }
}

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
    /// open the file, or packaged migrations cannot be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LocalDatabaseError> {
        Self::open_with_packaged_migrations(path, PACKAGED_MIGRATIONS)
    }

    /// Opens or creates a local `SQLite` database with the supplied packaged migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, `SQLite` cannot
    /// open the file, or a packaged migration cannot be applied.
    pub fn open_with_packaged_migrations(
        path: impl AsRef<Path>,
        migrations: &[PackagedMigration],
    ) -> Result<Self, LocalDatabaseError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(LocalDatabaseError::Io)?;
        }
        let mut connection = Connection::open(path).map_err(LocalDatabaseError::Sqlite)?;
        apply_packaged_migrations(&mut connection, migrations)?;
        validate_current_schema(&connection)?;
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

fn apply_packaged_migrations(
    connection: &mut Connection,
    migrations: &[PackagedMigration],
) -> Result<(), LocalDatabaseError> {
    for migration in migrations {
        if !migration_is_applied(connection, migration.version)? {
            apply_packaged_migration(connection, migration)?;
        }
    }
    Ok(())
}

fn validate_current_schema(connection: &Connection) -> Result<(), LocalDatabaseError> {
    let schema_version = connection_schema_version(connection)?;
    let mut missing_columns = Vec::new();

    for required_column in required_schema_columns(schema_version) {
        if !schema_column_exists(
            connection,
            required_column.table_name,
            required_column.column_name,
        )? {
            missing_columns.push(format!(
                "{}.{}",
                required_column.table_name, required_column.column_name
            ));
        }
    }

    if missing_columns.is_empty() {
        Ok(())
    } else {
        Err(LocalDatabaseError::Schema(format!(
            "schema version {schema_version} missing required columns: {}",
            missing_columns.join(", ")
        )))
    }
}

fn required_schema_columns(schema_version: u32) -> &'static [RequiredSchemaColumn] {
    match schema_version {
        INITIAL_SCHEMA_VERSION => SCHEMA_VERSION_1_REQUIRED_COLUMNS,
        _ => &[],
    }
}

fn connection_schema_version(connection: &Connection) -> Result<u32, LocalDatabaseError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(LocalDatabaseError::Sqlite)?;
    u32::try_from(version).map_err(|_| {
        LocalDatabaseError::Schema(format!("schema version {version} cannot be negative"))
    })
}

fn schema_column_exists(
    connection: &Connection,
    table_name: &str,
    column_name: &str,
) -> Result<bool, LocalDatabaseError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM pragma_table_info(?1)
             WHERE name = ?2",
            params![table_name, column_name],
            |row| row.get(0),
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    Ok(count == 1)
}

fn migration_is_applied(connection: &Connection, version: u32) -> Result<bool, LocalDatabaseError> {
    if !migration_ledger_exists(connection)? {
        return Ok(false);
    }

    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM schema_migrations
             WHERE version = ?1",
            params![i64::from(version)],
            |row| row.get(0),
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    Ok(count > 0)
}

fn migration_ledger_exists(connection: &Connection) -> Result<bool, LocalDatabaseError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |row| row.get(0),
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    Ok(count == 1)
}

fn apply_packaged_migration(
    connection: &mut Connection,
    migration: &PackagedMigration,
) -> Result<(), LocalDatabaseError> {
    let transaction = connection
        .transaction()
        .map_err(LocalDatabaseError::Sqlite)?;
    transaction
        .execute_batch(MIGRATION_LEDGER_SQL)
        .map_err(|source| migration_error(migration, source))?;
    transaction
        .execute_batch(migration.sql)
        .map_err(|source| migration_error(migration, source))?;
    transaction
        .execute(
            "INSERT INTO schema_migrations(version, name)
             VALUES (?1, ?2)",
            params![i64::from(migration.version), migration.name],
        )
        .map_err(|source| migration_error(migration, source))?;
    transaction
        .pragma_update(None, "user_version", i64::from(migration.version))
        .map_err(|source| migration_error(migration, source))?;
    transaction
        .commit()
        .map_err(|source| migration_error(migration, source))
}

fn migration_error(migration: &PackagedMigration, source: rusqlite::Error) -> LocalDatabaseError {
    LocalDatabaseError::Migration {
        name: migration.name.to_owned(),
        source,
    }
}

/// Errors returned by local database operations.
#[derive(Debug)]
pub enum LocalDatabaseError {
    /// Filesystem setup failed before `SQLite` opened the database.
    Io(std::io::Error),
    /// `SQLite` failed while opening, migrating, or reading the database.
    Sqlite(rusqlite::Error),
    /// The database reports a current schema version but is missing required
    /// current-schema objects.
    Schema(String),
    /// A named packaged migration failed and its transaction was rolled back.
    Migration {
        /// Packaged migration name, for example `0001-initial`.
        name: String,
        /// Underlying `SQLite` error that failed the migration.
        source: rusqlite::Error,
    },
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
            LocalDatabaseError::Schema(error) => {
                write!(formatter, "local database schema error: {error}")
            }
            LocalDatabaseError::Migration { name, source } => {
                write!(
                    formatter,
                    "local database migration {name} failed: {source}"
                )
            }
        }
    }
}

impl Error for LocalDatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LocalDatabaseError::Io(error) => Some(error),
            LocalDatabaseError::Sqlite(error) => Some(error),
            LocalDatabaseError::Schema(_) => None,
            LocalDatabaseError::Migration { source, .. } => Some(source),
        }
    }
}
