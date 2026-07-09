// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Local `SQLite` database for the air-gapped compliance corpus.
//!
//! The database is a queryable local index over the persisted scan corpus. The
//! MAT-94 content-addressed evidence store remains the backing store for
//! evidence bytes; this module stores only local `SQLite` rows and integrity
//! metadata.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::matrix::Corpus;
use rusqlite::{params, Connection};
use sovri_sdk::{ControlResult, EvidenceStore, Status};

/// The schema version created by the first packaged migration.
pub const INITIAL_SCHEMA_VERSION: u32 = 1;

const PACKAGED_MIGRATIONS: &[PackagedMigration] = &[
    PackagedMigration::new(INITIAL_SCHEMA_VERSION, "0001-initial", INITIAL_SCHEMA_SQL),
    PackagedMigration::new(
        RUN_EVIDENCE_LINKS_SCHEMA_VERSION,
        "0002-run-evidence-links",
        RUN_EVIDENCE_LINKS_SCHEMA_SQL,
    ),
    PackagedMigration::new(
        GAP_QUERY_FILTERS_SCHEMA_VERSION,
        "0003-gap-query-filters",
        GAP_QUERY_FILTERS_SCHEMA_SQL,
    ),
    PackagedMigration::new(
        EVIDENCE_LOCATORS_SCHEMA_VERSION,
        "0004-evidence-locators",
        EVIDENCE_LOCATORS_SCHEMA_SQL,
    ),
    PackagedMigration::new(
        RESULT_QUERY_FILTERS_SCHEMA_VERSION,
        "0005-result-query-filters",
        RESULT_QUERY_FILTERS_SCHEMA_SQL,
    ),
    PackagedMigration::new(
        RUN_EVIDENCE_INDEX_SCHEMA_VERSION,
        "0006-run-evidence-index",
        RUN_EVIDENCE_INDEX_SCHEMA_SQL,
    ),
];

const INITIAL_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS scan_runs (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS frameworks (
      id TEXT PRIMARY KEY,
      version TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS controls (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS control_results (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL DEFAULT '',
      control_id TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT '',
      evidence_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS compliance_gaps (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      control_id TEXT NOT NULL,
      rule_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS evidence_metadata (
      id TEXT PRIMARY KEY,
      digest TEXT NOT NULL,
      locator TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS run_evidence_links (
      run_id TEXT NOT NULL,
      evidence_id TEXT NOT NULL,
      PRIMARY KEY (run_id, evidence_id)
    );
    CREATE TABLE IF NOT EXISTS score_summaries (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS exports (id TEXT PRIMARY KEY);
";

const RUN_EVIDENCE_LINKS_SCHEMA_VERSION: u32 = 2;

const RUN_EVIDENCE_LINKS_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS run_evidence_links (
      run_id TEXT NOT NULL,
      evidence_id TEXT NOT NULL,
      PRIMARY KEY (run_id, evidence_id)
    );
    INSERT OR IGNORE INTO run_evidence_links(run_id, evidence_id)
    SELECT run_id, id
    FROM evidence_metadata;
";

const GAP_QUERY_FILTERS_SCHEMA_VERSION: u32 = 3;

const GAP_QUERY_FILTERS_SCHEMA_SQL: &str = "";
const GAP_QUERY_FILTER_COLUMNS: &[&str] =
    &["run_id", "status", "severity", "control_id", "rule_id"];

const EVIDENCE_LOCATORS_SCHEMA_VERSION: u32 = 4;

const EVIDENCE_LOCATORS_SCHEMA_SQL: &str = "";

const RESULT_QUERY_FILTERS_SCHEMA_VERSION: u32 = 5;

const RESULT_QUERY_FILTERS_SCHEMA_SQL: &str = "";

const RUN_EVIDENCE_INDEX_SCHEMA_VERSION: u32 = 6;

const RUN_EVIDENCE_INDEX_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS run_evidence_links (
      run_id TEXT NOT NULL,
      evidence_id TEXT NOT NULL,
      PRIMARY KEY (run_id, evidence_id)
    );
    INSERT OR IGNORE INTO run_evidence_links(run_id, evidence_id)
    SELECT DISTINCT run_id, evidence_id
    FROM control_results
    WHERE run_id <> '' AND evidence_id <> '';
    INSERT OR IGNORE INTO run_evidence_links(run_id, evidence_id)
    SELECT scan_runs.id, evidence_metadata.id
    FROM scan_runs
    CROSS JOIN evidence_metadata
    WHERE (SELECT COUNT(*) FROM scan_runs) = 1;
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

const SCHEMA_VERSION_3_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
];

const SCHEMA_VERSION_4_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("control_results", "control_id"),
    RequiredSchemaColumn::new("control_results", "evidence_id"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("evidence_metadata", "locator"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
];

const SCHEMA_VERSION_5_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("control_results", "run_id"),
    RequiredSchemaColumn::new("control_results", "control_id"),
    RequiredSchemaColumn::new("control_results", "rule_id"),
    RequiredSchemaColumn::new("control_results", "status"),
    RequiredSchemaColumn::new("control_results", "evidence_id"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("evidence_metadata", "locator"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
];

const SCHEMA_VERSION_6_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("control_results", "run_id"),
    RequiredSchemaColumn::new("control_results", "control_id"),
    RequiredSchemaColumn::new("control_results", "rule_id"),
    RequiredSchemaColumn::new("control_results", "status"),
    RequiredSchemaColumn::new("control_results", "evidence_id"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("evidence_metadata", "locator"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
    RequiredSchemaColumn::new("run_evidence_links", "run_id"),
    RequiredSchemaColumn::new("run_evidence_links", "evidence_id"),
];

const NO_REQUIRED_SCHEMA_COLUMNS: &[RequiredSchemaColumn] = &[];

const SUPPORTED_SCHEMA_REQUIREMENTS: &[SchemaRequirements] = &[
    SchemaRequirements::new(INITIAL_SCHEMA_VERSION, SCHEMA_VERSION_1_REQUIRED_COLUMNS),
    SchemaRequirements::new(
        RUN_EVIDENCE_LINKS_SCHEMA_VERSION,
        SCHEMA_VERSION_1_REQUIRED_COLUMNS,
    ),
    SchemaRequirements::new(
        GAP_QUERY_FILTERS_SCHEMA_VERSION,
        SCHEMA_VERSION_3_REQUIRED_COLUMNS,
    ),
    SchemaRequirements::new(
        EVIDENCE_LOCATORS_SCHEMA_VERSION,
        SCHEMA_VERSION_4_REQUIRED_COLUMNS,
    ),
    SchemaRequirements::new(
        RESULT_QUERY_FILTERS_SCHEMA_VERSION,
        SCHEMA_VERSION_5_REQUIRED_COLUMNS,
    ),
    SchemaRequirements::new(
        RUN_EVIDENCE_INDEX_SCHEMA_VERSION,
        SCHEMA_VERSION_6_REQUIRED_COLUMNS,
    ),
];

#[derive(Clone, Copy, Debug)]
struct SchemaRequirements {
    version: u32,
    required_columns: &'static [RequiredSchemaColumn],
}

impl SchemaRequirements {
    const fn new(version: u32, required_columns: &'static [RequiredSchemaColumn]) -> Self {
        SchemaRequirements {
            version,
            required_columns,
        }
    }
}

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

/// A persisted compliance gap returned by local database queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDatabaseGap {
    control_id: String,
    rule_id: String,
    status: String,
}

/// A persisted control result returned by local database queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDatabaseResult {
    run_id: String,
    status: String,
}

/// Persisted evidence metadata returned by local database queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDatabaseEvidence {
    id: String,
    digest: String,
    locator: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceLookup {
    Id,
    Digest,
    Control,
}

impl EvidenceLookup {
    // Lookup names are intentionally exact and case-sensitive.
    fn parse(lookup: &str) -> Option<Self> {
        match lookup {
            "id" => Some(EvidenceLookup::Id),
            "digest" => Some(EvidenceLookup::Digest),
            "control" => Some(EvidenceLookup::Control),
            _ => None,
        }
    }
}

impl LocalDatabaseGap {
    /// Returns the control id for the compliance gap.
    #[must_use]
    pub fn control_id(&self) -> &str {
        &self.control_id
    }

    /// Returns the rule id for the compliance gap.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the persisted result status for the compliance gap.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
}

impl LocalDatabaseResult {
    /// Returns the scan run that produced the result.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the persisted result status.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
}

impl LocalDatabaseEvidence {
    /// Returns the stable evidence id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the expected content digest persisted by `SQLite`.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the persisted evidence locator.
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
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
        validate_current_schema(&connection, migrations)?;
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

    /// Queries persisted scan run ids in stable order.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot prepare or run the run-list query.
    pub fn query_runs(&self) -> Result<Vec<String>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM scan_runs ORDER BY id")
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Queries a persisted scan run by id.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot prepare or run the run query.
    pub fn query_run(&self, run_id: &str) -> Result<Vec<String>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM scan_runs WHERE id = ?1")
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map(params![run_id], |row| row.get::<_, String>(0))
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Queries persisted compliance gaps by run, status, and severity.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot prepare or run the gap-list query.
    pub fn query_gaps(
        &self,
        run_id: &str,
        status: &str,
        severity: &str,
    ) -> Result<Vec<LocalDatabaseGap>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT control_id, rule_id, status
                 FROM compliance_gaps
                 WHERE run_id = ?1 AND status = ?2 AND severity = ?3
                 ORDER BY control_id, rule_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map(params![run_id, status, severity], |row| {
                Ok(LocalDatabaseGap {
                    control_id: row.get(0)?,
                    rule_id: row.get(1)?,
                    status: row.get(2)?,
                })
            })
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Queries persisted control results by run, control, and status.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot prepare or run the result-list query.
    pub fn query_results(
        &self,
        run_id: &str,
        control_id: &str,
        status: &str,
    ) -> Result<Vec<LocalDatabaseResult>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT run_id, status
                 FROM control_results
                 WHERE run_id = ?1 AND control_id = ?2 AND status = ?3
                 ORDER BY rule_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map(params![run_id, control_id, status], |row| {
                Ok(LocalDatabaseResult {
                    run_id: row.get(0)?,
                    status: row.get(1)?,
                })
            })
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Queries persisted evidence metadata by id, digest, or control id.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot prepare or run the evidence-list query.
    pub fn query_evidence(
        &self,
        lookup: &str,
        value: &str,
    ) -> Result<Vec<LocalDatabaseEvidence>, LocalDatabaseError> {
        let Some(lookup) = EvidenceLookup::parse(lookup) else {
            return Ok(Vec::new());
        };
        let sql = match lookup {
            EvidenceLookup::Id => {
                "SELECT id, digest, locator
                 FROM evidence_metadata
                 WHERE id = ?1
                 ORDER BY id"
            }
            EvidenceLookup::Digest => {
                "SELECT id, digest, locator
                 FROM evidence_metadata
                 WHERE digest = ?1
                 ORDER BY id"
            }
            EvidenceLookup::Control => {
                "SELECT DISTINCT evidence_metadata.id, evidence_metadata.digest,
                                 evidence_metadata.locator
                 FROM evidence_metadata
                 INNER JOIN control_results
                   ON control_results.evidence_id = evidence_metadata.id
                 WHERE control_results.control_id = ?1
                 ORDER BY evidence_metadata.id"
            }
        };
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map(params![value], |row| {
                Ok(LocalDatabaseEvidence {
                    id: row.get("id")?,
                    digest: row.get("digest")?,
                    locator: row.get("locator")?,
                })
            })
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Reads linked evidence metadata when its expected digest resolves to the
    /// same evidence id in the content-addressed store.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read the linked evidence metadata or
    /// the backing store resolves the evidence id to a different digest.
    pub fn read_linked_evidence(
        &self,
        store: &EvidenceStore,
        evidence_id: &str,
    ) -> Result<Option<LocalDatabaseEvidence>, LocalDatabaseError> {
        let Some(metadata) = self.query_evidence("id", evidence_id)?.into_iter().next() else {
            return Ok(None);
        };
        let index = store.index();
        if metadata.digest().is_empty() {
            return Ok(index
                .resolve_id(metadata.id())
                .is_some()
                .then_some(metadata));
        }
        if index
            .resolve_digest(metadata.digest())
            .is_some_and(|record| {
                record.id() == metadata.id() && record.content_hash() == metadata.digest()
            })
        {
            return Ok(Some(metadata));
        }
        let Some(record) = index.resolve_id(metadata.id()) else {
            return Ok(None);
        };
        Err(LocalDatabaseError::IntegrityMismatch {
            evidence_id: metadata.id().to_owned(),
            expected: metadata.digest().to_owned(),
            actual: record.content_hash().to_owned(),
        })
    }

    /// Validates all evidence linked to a run before corpus reconstruction.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read the run links or linked metadata,
    /// or if a backing-store digest differs from the persisted expected digest.
    pub fn validate_corpus_reconstruction(
        &self,
        store: &EvidenceStore,
        run_id: &str,
    ) -> Result<(), LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT evidence_id
                 FROM run_evidence_links
                 WHERE run_id = ?1
                 ORDER BY evidence_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let evidence_ids = statement
            .query_map(params![run_id], |row| row.get::<_, String>(0))
            .map_err(LocalDatabaseError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)?;

        for evidence_id in evidence_ids {
            self.read_linked_evidence(store, &evidence_id)?;
        }
        Ok(())
    }

    /// Writes a completed scan corpus into the local database.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot start, populate, or commit the write
    /// transaction.
    pub fn write_completed_corpus(&mut self, corpus: &Corpus) -> Result<(), LocalDatabaseError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(LocalDatabaseError::Sqlite)?;
        let run_id = corpus.run_id();
        let scoped_results = corpus.scoped_results();

        transaction
            .execute(
                "INSERT INTO scan_runs(id) VALUES (?1)
                 ON CONFLICT(id) DO NOTHING",
                params![run_id],
            )
            .map_err(LocalDatabaseError::Sqlite)?;

        for (framework_id, version, _source_url) in corpus.frameworks() {
            transaction
                .execute(
                    "INSERT INTO frameworks(id, version) VALUES (?1, ?2)
                     ON CONFLICT(id) DO NOTHING",
                    params![framework_id, version],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }

        for (_, control_id, _, _) in corpus.controls() {
            transaction
                .execute(
                    "INSERT INTO controls(id) VALUES (?1)
                     ON CONFLICT(id) DO NOTHING",
                    params![control_id],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }

        for framework_id in scoped_results
            .iter()
            .filter_map(|(framework_id, _)| *framework_id)
            .collect::<BTreeSet<_>>()
        {
            transaction
                .execute(
                    "INSERT INTO score_summaries(id) VALUES (?1)
                     ON CONFLICT(id) DO NOTHING",
                    params![framework_id],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }

        for (framework_id, result) in &scoped_results {
            let evidence_id = result
                .evidence_refs()
                .first()
                .map(String::as_str)
                .unwrap_or_default();
            let result_id = control_result_row_id(
                run_id,
                framework_id.unwrap_or_default(),
                result.control_id(),
                result.rule_id(),
            );
            transaction
                .execute(
                    "INSERT INTO control_results(
                       id,
                       run_id,
                       control_id,
                       rule_id,
                       status,
                       evidence_id
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(id) DO UPDATE SET
                       run_id = COALESCE(NULLIF(control_results.run_id, ''), excluded.run_id),
                       status = COALESCE(NULLIF(control_results.status, ''), excluded.status)",
                    params![
                        result_id,
                        run_id,
                        result.control_id(),
                        result.rule_id(),
                        result.status().label(),
                        evidence_id
                    ],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }

        write_gap_rows(&transaction, run_id, &scoped_results)?;

        write_evidence_rows(&transaction, run_id, corpus).map_err(LocalDatabaseError::Sqlite)?;

        transaction.commit().map_err(LocalDatabaseError::Sqlite)
    }
}

fn write_evidence_rows(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    corpus: &Corpus,
) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM run_evidence_links WHERE run_id = ?1",
        params![run_id],
    )?;
    for evidence in corpus.evidence_records() {
        transaction.execute(
            // Rewrites refresh content identity but preserve the first non-empty locator.
            "INSERT INTO evidence_metadata(id, digest, locator)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
               digest = COALESCE(NULLIF(excluded.digest, ''), evidence_metadata.digest),
               locator = CASE
                 WHEN evidence_metadata.locator = '' THEN excluded.locator
                 ELSE evidence_metadata.locator
               END",
            params![evidence.id, evidence.integrity, evidence.locator],
        )?;
        transaction.execute(
            "INSERT INTO run_evidence_links(run_id, evidence_id)
             VALUES (?1, ?2)
             ON CONFLICT(run_id, evidence_id) DO NOTHING",
            params![run_id, evidence.id],
        )?;
    }
    Ok(())
}

fn control_result_row_id(
    run_id: &str,
    framework_id: &str,
    control_id: &str,
    rule_id: &str,
) -> String {
    format!(
        "{}:{run_id}:{}:{framework_id}:{}:{control_id}:{rule_id}",
        run_id.len(),
        framework_id.len(),
        control_id.len()
    )
}

fn write_gap_rows(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    scoped_results: &[(Option<&str>, &ControlResult)],
) -> Result<(), LocalDatabaseError> {
    for (framework_id, result) in scoped_results.iter().filter_map(|(framework_id, result)| {
        framework_id.map(|framework_id| (framework_id, *result))
    }) {
        if is_gap_status(result.status()) {
            let legacy_gap_id =
                legacy_compliance_gap_row_id(framework_id, result.control_id(), result.rule_id());
            let gap_id =
                compliance_gap_row_id(run_id, framework_id, result.control_id(), result.rule_id());
            transaction
                .execute(
                    "DELETE FROM compliance_gaps WHERE id = ?1",
                    params![legacy_gap_id],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
            transaction
                .execute(
                    "INSERT INTO compliance_gaps(
                       id,
                       run_id,
                       status,
                       severity,
                       control_id,
                       rule_id
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(id) DO NOTHING",
                    params![
                        gap_id,
                        run_id,
                        result.status().label(),
                        result.severity(),
                        result.control_id(),
                        result.rule_id()
                    ],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }
    }
    Ok(())
}

fn compliance_gap_row_id(
    run_id: &str,
    framework_id: &str,
    control_id: &str,
    rule_id: &str,
) -> String {
    format!(
        "{}:{run_id}:{}:{framework_id}:{}:{control_id}:{}:{rule_id}",
        run_id.len(),
        framework_id.len(),
        control_id.len(),
        rule_id.len()
    )
}

fn legacy_compliance_gap_row_id(framework_id: &str, control_id: &str, rule_id: &str) -> String {
    format!(
        "{}:{framework_id}:{}:{control_id}:{rule_id}",
        framework_id.len(),
        control_id.len()
    )
}

fn is_gap_status(status: Status) -> bool {
    matches!(status, Status::Fail | Status::Warning)
}

fn apply_packaged_migrations(
    connection: &mut Connection,
    migrations: &[PackagedMigration],
) -> Result<(), LocalDatabaseError> {
    for migration in migrations {
        if !migration_is_applied(connection, migration.version)?
            && migration_is_applicable(connection, migration)?
        {
            apply_packaged_migration(connection, migration)?;
        }
    }
    Ok(())
}

fn validate_current_schema(
    connection: &Connection,
    migrations: &[PackagedMigration],
) -> Result<(), LocalDatabaseError> {
    let schema_version = connection_schema_version(connection)?;
    if schema_version != 0 && !migration_is_applied(connection, schema_version)? {
        return Err(LocalDatabaseError::Schema(format!(
            "unsupported schema version {schema_version}; schema_migrations does not record that version"
        )));
    }

    let mut missing_columns = Vec::new();

    for required_column in required_schema_columns(schema_version, migrations)? {
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
            "schema version {schema_version} failed validation; missing {} required column(s): {}",
            missing_columns.len(),
            missing_columns.join(", ")
        )))
    }
}

/// Returns the column requirements for the schema version this database reports.
/// Exact known versions use version-specific requirements. Caller-supplied
/// newer migrations retain the latest known requirements, while versions not
/// produced by the supplied migration stack are rejected.
fn required_schema_columns(
    schema_version: u32,
    migrations: &[PackagedMigration],
) -> Result<&'static [RequiredSchemaColumn], LocalDatabaseError> {
    if schema_version == 0 {
        return Err(LocalDatabaseError::Schema(
            "schema version 0 is uninitialized; expected a migrated local database".to_owned(),
        ));
    }

    if !uses_supported_schema_requirements(migrations) {
        return if migration_version_is_supplied(schema_version, migrations) {
            Ok(NO_REQUIRED_SCHEMA_COLUMNS)
        } else {
            Err(unsupported_schema_version(schema_version, migrations))
        };
    }

    if let Some(requirements) = SUPPORTED_SCHEMA_REQUIREMENTS
        .iter()
        .find(|requirements| requirements.version == schema_version)
    {
        return Ok(requirements.required_columns);
    }

    let latest_requirements = latest_supported_schema_requirements();
    if schema_version > latest_requirements.version
        && migration_version_is_supplied(schema_version, migrations)
    {
        return Ok(latest_requirements.required_columns);
    }

    Err(unsupported_schema_version(schema_version, migrations))
}

fn uses_supported_schema_requirements(migrations: &[PackagedMigration]) -> bool {
    migrations.iter().any(|migration| {
        PACKAGED_MIGRATIONS.iter().any(|packaged_migration| {
            migration.version == packaged_migration.version
                && migration.name == packaged_migration.name
                && migration.sql == packaged_migration.sql
        })
    })
}

fn migration_version_is_supplied(schema_version: u32, migrations: &[PackagedMigration]) -> bool {
    migrations
        .iter()
        .any(|migration| migration.version == schema_version)
}

fn unsupported_schema_version(
    schema_version: u32,
    migrations: &[PackagedMigration],
) -> LocalDatabaseError {
    LocalDatabaseError::Schema(format!(
        "unsupported schema version {schema_version}; supplied packaged migration versions: {}",
        packaged_migration_versions(migrations)
    ))
}

fn latest_supported_schema_requirements() -> &'static SchemaRequirements {
    SUPPORTED_SCHEMA_REQUIREMENTS
        .iter()
        .max_by_key(|requirements| requirements.version)
        .expect("at least one local database schema requirement is packaged")
}

fn packaged_migration_versions(migrations: &[PackagedMigration]) -> String {
    let versions = migrations
        .iter()
        .map(|migration| migration.version)
        .collect::<std::collections::BTreeSet<_>>();

    if versions.is_empty() {
        return "none".to_owned();
    }

    versions
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
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

fn migration_is_applicable(
    connection: &Connection,
    migration: &PackagedMigration,
) -> Result<bool, LocalDatabaseError> {
    if migration.version == RUN_EVIDENCE_LINKS_SCHEMA_VERSION
        && migration.name == "0002-run-evidence-links"
        && migration.sql == RUN_EVIDENCE_LINKS_SCHEMA_SQL
    {
        return schema_column_exists(connection, "evidence_metadata", "run_id");
    }

    if migration.version == GAP_QUERY_FILTERS_SCHEMA_VERSION
        && migration.name == "0003-gap-query-filters"
        && migration.sql == GAP_QUERY_FILTERS_SCHEMA_SQL
    {
        return Ok(schema_column_exists(connection, "compliance_gaps", "id")?
            && !schema_column_exists(connection, "compliance_gaps", "run_id")?);
    }

    if migration.version == EVIDENCE_LOCATORS_SCHEMA_VERSION
        && migration.name == "0004-evidence-locators"
        && migration.sql == EVIDENCE_LOCATORS_SCHEMA_SQL
    {
        return Ok(schema_column_exists(connection, "evidence_metadata", "id")?
            && schema_column_exists(connection, "control_results", "control_id")?
            && schema_column_exists(connection, "control_results", "evidence_id")?
            && !schema_column_exists(connection, "evidence_metadata", "locator")?);
    }

    if migration.version == RESULT_QUERY_FILTERS_SCHEMA_VERSION
        && migration.name == "0005-result-query-filters"
        && migration.sql == RESULT_QUERY_FILTERS_SCHEMA_SQL
    {
        return Ok(schema_column_exists(connection, "control_results", "id")?
            && (!schema_column_exists(connection, "control_results", "run_id")?
                || !schema_column_exists(connection, "control_results", "status")?));
    }

    if migration.version == RUN_EVIDENCE_INDEX_SCHEMA_VERSION
        && migration.name == "0006-run-evidence-index"
        && migration.sql == RUN_EVIDENCE_INDEX_SCHEMA_SQL
    {
        let schema_version = connection_schema_version(connection)?;
        let link_columns_missing =
            !schema_column_exists(connection, "run_evidence_links", "run_id")?
                || !schema_column_exists(connection, "run_evidence_links", "evidence_id")?;
        let can_backfill = schema_column_exists(connection, "scan_runs", "id")?
            && schema_column_exists(connection, "evidence_metadata", "id")?
            && schema_column_exists(connection, "control_results", "run_id")?
            && schema_column_exists(connection, "control_results", "evidence_id")?;
        return Ok((INITIAL_SCHEMA_VERSION..RUN_EVIDENCE_INDEX_SCHEMA_VERSION)
            .contains(&schema_version)
            && migration_is_applied(connection, schema_version)?
            && can_backfill
            && (schema_version > INITIAL_SCHEMA_VERSION || link_columns_missing));
    }

    Ok(true)
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
    if migration.version == GAP_QUERY_FILTERS_SCHEMA_VERSION
        && migration.name == "0003-gap-query-filters"
        && migration.sql == GAP_QUERY_FILTERS_SCHEMA_SQL
    {
        apply_gap_query_filters_migration(&transaction)
            .map_err(|source| migration_error(migration, source))?;
    } else if migration.version == EVIDENCE_LOCATORS_SCHEMA_VERSION
        && migration.name == "0004-evidence-locators"
        && migration.sql == EVIDENCE_LOCATORS_SCHEMA_SQL
    {
        apply_evidence_locators_migration(&transaction)
            .map_err(|source| migration_error(migration, source))?;
    } else if migration.version == RESULT_QUERY_FILTERS_SCHEMA_VERSION
        && migration.name == "0005-result-query-filters"
        && migration.sql == RESULT_QUERY_FILTERS_SCHEMA_SQL
    {
        apply_result_query_filters_migration(&transaction)
            .map_err(|source| migration_error(migration, source))?;
    } else {
        transaction
            .execute_batch(migration.sql)
            .map_err(|source| migration_error(migration, source))?;
    }
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

fn apply_gap_query_filters_migration(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    for column_name in GAP_QUERY_FILTER_COLUMNS {
        if !transaction_schema_column_exists(transaction, "compliance_gaps", column_name)? {
            let sql = format!("ALTER TABLE compliance_gaps ADD COLUMN {column_name} TEXT");
            transaction.execute(&sql, [])?;
        }
    }

    Ok(())
}

fn apply_evidence_locators_migration(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    if !transaction_schema_column_exists(transaction, "evidence_metadata", "locator")? {
        transaction.execute(
            "ALTER TABLE evidence_metadata ADD COLUMN locator TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }

    Ok(())
}

fn apply_result_query_filters_migration(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    if !transaction_schema_column_exists(transaction, "control_results", "run_id")? {
        transaction.execute(
            "ALTER TABLE control_results ADD COLUMN run_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !transaction_schema_column_exists(transaction, "control_results", "status")? {
        transaction.execute(
            "ALTER TABLE control_results ADD COLUMN status TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }

    backfill_control_result_run_ids(transaction)?;
    transaction.execute(
        "UPDATE control_results
         SET status = COALESCE(
           (
             SELECT compliance_gaps.status
             FROM compliance_gaps
             WHERE compliance_gaps.run_id = control_results.run_id
               AND compliance_gaps.control_id = control_results.control_id
               AND compliance_gaps.rule_id = control_results.rule_id
             ORDER BY compliance_gaps.id
             LIMIT 1
           ),
           control_results.status
         )
         WHERE status = ''",
        [],
    )?;

    Ok(())
}

fn backfill_control_result_run_ids(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    let mut statement = transaction.prepare("SELECT id FROM control_results")?;
    let row_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for row_id in row_ids {
        if let Some(run_id) = control_result_run_id(&row_id) {
            transaction.execute(
                "UPDATE control_results SET run_id = ?1 WHERE id = ?2",
                params![run_id, row_id],
            )?;
        }
    }

    Ok(())
}

fn control_result_run_id(row_id: &str) -> Option<&str> {
    let (run_id, remainder) = take_length_prefixed_field(row_id)?;
    let (_, remainder) = take_length_prefixed_field(remainder)?;
    let (_, rule_id) = take_length_prefixed_field(remainder)?;
    (!run_id.is_empty() && !rule_id.is_empty()).then_some(run_id)
}

fn take_length_prefixed_field(input: &str) -> Option<(&str, &str)> {
    let (length, remainder) = input.split_once(':')?;
    let length = length.parse::<usize>().ok()?;
    let value = remainder.get(..length)?;
    let remainder = remainder.get(length..)?.strip_prefix(':')?;
    Some((value, remainder))
}

fn transaction_schema_column_exists(
    transaction: &rusqlite::Transaction<'_>,
    table_name: &str,
    column_name: &str,
) -> rusqlite::Result<bool> {
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*)
         FROM pragma_table_info(?1)
         WHERE name = ?2",
        params![table_name, column_name],
        |row| row.get(0),
    )?;
    Ok(count == 1)
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
    /// Linked evidence resolved to a digest different from the one persisted by
    /// `SQLite`.
    IntegrityMismatch {
        /// Stable evidence id being resolved.
        evidence_id: String,
        /// Digest persisted by `SQLite`.
        expected: String,
        /// Digest resolved from the content-addressed store.
        actual: String,
    },
    /// A named packaged migration failed and its transaction was rolled back.
    Migration {
        /// Packaged migration name, for example `0001-initial`.
        name: String,
        /// Underlying `SQLite` error that failed the migration.
        source: rusqlite::Error,
    },
}

impl LocalDatabaseError {
    /// Whether this error reports a linked-evidence integrity mismatch.
    #[must_use]
    pub fn is_integrity_error(&self) -> bool {
        matches!(self, LocalDatabaseError::IntegrityMismatch { .. })
    }

    /// Returns the expected digest for a linked-evidence integrity mismatch.
    #[must_use]
    pub fn expected_digest(&self) -> Option<&str> {
        match self {
            LocalDatabaseError::IntegrityMismatch { expected, .. } => Some(expected),
            _ => None,
        }
    }

    /// Returns the actual digest for a linked-evidence integrity mismatch.
    #[must_use]
    pub fn actual_digest(&self) -> Option<&str> {
        match self {
            LocalDatabaseError::IntegrityMismatch { actual, .. } => Some(actual),
            _ => None,
        }
    }
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
            LocalDatabaseError::IntegrityMismatch {
                evidence_id,
                expected,
                actual,
            } => write!(
                formatter,
                "linked evidence {evidence_id} integrity mismatch: expected {expected}, actual {actual}"
            ),
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
            LocalDatabaseError::Schema(_) | LocalDatabaseError::IntegrityMismatch { .. } => None,
            LocalDatabaseError::Migration { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewriting_a_run_replaces_its_evidence_links() {
        let mut connection = Connection::open_in_memory().expect("open in-memory SQLite");
        apply_packaged_migrations(&mut connection, PACKAGED_MIGRATIONS)
            .expect("apply packaged migrations");
        let mut database = LocalDatabase { connection };
        database
            .write_completed_corpus(
                &Corpus::new("2026-06-24T13:16:28Z")
                    .with_run_id("rewritten-run")
                    .with_evidence("old-evidence", "old.locator")
                    .with_evidence("kept-evidence", "kept.locator"),
            )
            .expect("write the original run");

        database
            .write_completed_corpus(
                &Corpus::new("2026-06-24T13:16:28Z")
                    .with_run_id("rewritten-run")
                    .with_evidence("kept-evidence", "kept.locator"),
            )
            .expect("rewrite the run");

        let links = database
            .connection
            .prepare(
                "SELECT evidence_id
                 FROM run_evidence_links
                 WHERE run_id = 'rewritten-run'
                 ORDER BY evidence_id",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(links, vec!["kept-evidence"]);
    }

    #[test]
    fn run_evidence_index_migration_backfills_a_recognized_v5_database() {
        let mut connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(INITIAL_SCHEMA_SQL)
            .expect("create the current table shapes");
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (
                   version INTEGER PRIMARY KEY,
                   name TEXT NOT NULL,
                   applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO schema_migrations(version, name) VALUES
                   (1, '0001-initial'),
                   (3, '0003-gap-query-filters'),
                   (4, '0004-evidence-locators'),
                   (5, '0005-result-query-filters');
                 INSERT INTO scan_runs(id) VALUES ('existing-run');
                 INSERT INTO evidence_metadata(id, digest, locator) VALUES
                   ('result-evidence', 'sha256:result', 'result.locator'),
                   ('standalone-evidence', 'sha256:standalone', 'standalone.locator');
                 INSERT INTO control_results(
                   id, run_id, control_id, rule_id, status, evidence_id
                 ) VALUES (
                   'existing-result', 'existing-run', 'control', 'rule', 'FAIL',
                   'result-evidence'
                 );
                 PRAGMA user_version = 5;",
            )
            .expect("record a recognized v5 schema");

        apply_packaged_migrations(&mut connection, PACKAGED_MIGRATIONS)
            .expect("apply the run-evidence repair migration");

        assert_eq!(connection_schema_version(&connection).unwrap(), 6);
        assert!(schema_column_exists(&connection, "run_evidence_links", "run_id").unwrap());
        assert!(schema_column_exists(&connection, "run_evidence_links", "evidence_id").unwrap());
        let links: Vec<(String, String)> = connection
            .prepare(
                "SELECT run_id, evidence_id
                 FROM run_evidence_links
                 ORDER BY evidence_id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            links,
            vec![
                ("existing-run".to_owned(), "result-evidence".to_owned()),
                ("existing-run".to_owned(), "standalone-evidence".to_owned()),
            ]
        );
    }

    #[test]
    fn evidence_lookup_parse_accepts_only_exact_names() {
        assert_eq!(EvidenceLookup::parse("id"), Some(EvidenceLookup::Id));
        assert_eq!(
            EvidenceLookup::parse("digest"),
            Some(EvidenceLookup::Digest)
        );
        assert_eq!(
            EvidenceLookup::parse("control"),
            Some(EvidenceLookup::Control)
        );
        assert_eq!(EvidenceLookup::parse("ID"), None);
        assert_eq!(EvidenceLookup::parse(" id "), None);
        assert_eq!(EvidenceLookup::parse(""), None);
    }

    #[test]
    fn control_result_run_id_rejects_legacy_and_malformed_ids() {
        let current_id = "16:mixed-2026-06-24:13:gdpr-eprivacy:29:consent.tracker.prior-consent:consent.detect-trackers-without-consent-evidence";
        assert_eq!(control_result_run_id(current_id), Some("mixed-2026-06-24"));

        let legacy_id =
            "29:consent.tracker.prior-consent:consent.detect-trackers-without-consent-evidence";
        assert_eq!(control_result_run_id(legacy_id), None);

        for malformed_id in ["", "not-a-length:value", "5:short", "1:r:1:f:1:c:"] {
            assert_eq!(control_result_run_id(malformed_id), None);
        }
    }

    #[test]
    fn schema_column_exists_is_false_for_missing_or_untrusted_names() {
        let connection = Connection::open_in_memory().expect("in-memory database opens");
        connection
            .execute_batch(
                "
                CREATE TABLE frameworks (
                  id TEXT PRIMARY KEY,
                  version TEXT NOT NULL
                );
                ",
            )
            .expect("schema can be created");

        assert!(schema_column_exists(&connection, "frameworks", "version")
            .expect("existing column can be checked"));
        assert!(
            !schema_column_exists(&connection, "missing_table", "version")
                .expect("missing table can be checked")
        );
        assert!(
            !schema_column_exists(&connection, "frameworks", "missing_column")
                .expect("missing column can be checked")
        );
        assert!(!schema_column_exists(
            &connection,
            "frameworks); DROP TABLE frameworks; --",
            "version"
        )
        .expect("untrusted table name can be checked"));
        assert!(schema_column_exists(&connection, "frameworks", "version")
            .expect("untrusted table name was not executed as SQL"));
    }
}
