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

use crate::matrix::{Classification, Corpus};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sovri_sdk::{ControlResult, EvidenceStore, Status};

#[cfg(test)]
use std::collections::BTreeSet;

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
    PackagedMigration::new(
        EVIDENCE_CLASSIFICATIONS_SCHEMA_VERSION,
        "0007-evidence-classifications",
        EVIDENCE_CLASSIFICATIONS_SCHEMA_SQL,
    ),
    PackagedMigration::new(
        EXPORT_RECONSTRUCTION_SCHEMA_VERSION,
        "0008-export-reconstruction",
        EXPORT_RECONSTRUCTION_SCHEMA_SQL,
    ),
];

const INITIAL_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS scan_runs (
      id TEXT PRIMARY KEY,
      executed_at TEXT NOT NULL DEFAULT ''
    );
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
      evidence_id TEXT NOT NULL,
      framework_id TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT '',
      weight INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      executed_at TEXT NOT NULL DEFAULT '',
      execution_metadata TEXT NOT NULL DEFAULT ''
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
      locator TEXT NOT NULL DEFAULT '',
      classification TEXT NOT NULL DEFAULT 'Unclassified'
    );
    CREATE TABLE IF NOT EXISTS run_evidence_links (
      run_id TEXT NOT NULL,
      evidence_id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT '',
      digest TEXT NOT NULL DEFAULT '',
      locator TEXT NOT NULL DEFAULT '',
      classification TEXT NOT NULL DEFAULT 'Unclassified',
      PRIMARY KEY (run_id, evidence_id)
    );
    CREATE TABLE IF NOT EXISTS run_framework_links (
      run_id TEXT NOT NULL,
      framework_id TEXT NOT NULL,
      version TEXT NOT NULL DEFAULT '',
      source_url TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (run_id, framework_id)
    );
    CREATE TABLE IF NOT EXISTS run_control_links (
      run_id TEXT NOT NULL,
      framework_id TEXT NOT NULL,
      control_id TEXT NOT NULL,
      title TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT '',
      weight INTEGER NOT NULL DEFAULT 0,
      reference TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (run_id, framework_id, control_id)
    );
    CREATE TABLE IF NOT EXISTS score_summaries (
      id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      framework_id TEXT NOT NULL,
      pass_count INTEGER NOT NULL,
      fail_count INTEGER NOT NULL,
      warning_count INTEGER NOT NULL
    );
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

// This domain policy is kept in exact sync with the current application schema
// by `hardcoded_persisted_corpus_tables_match_current_schema`.
const PERSISTED_CORPUS_TABLES: &[&str] = &[
    "scan_runs",
    "frameworks",
    "controls",
    "control_results",
    "compliance_gaps",
    "evidence_metadata",
    "score_summaries",
    "exports",
    "run_evidence_links",
    "run_framework_links",
    "run_control_links",
];

const GAP_QUERY_FILTERS_SCHEMA_VERSION: u32 = 3;

const GAP_QUERY_FILTERS_SCHEMA_SQL: &str = "";
const GAP_QUERY_FILTER_COLUMNS: &[&str] =
    &["run_id", "status", "severity", "control_id", "rule_id"];

const EVIDENCE_LOCATORS_SCHEMA_VERSION: u32 = 4;

const EVIDENCE_LOCATORS_SCHEMA_SQL: &str = "";

const RESULT_QUERY_FILTERS_SCHEMA_VERSION: u32 = 5;

const RESULT_QUERY_FILTERS_SCHEMA_SQL: &str = "";
const CONTROL_RESULT_QUERY_FILTER_COLUMNS: &[(&str, &str)] = &[
    ("run_id", "TEXT NOT NULL DEFAULT ''"),
    ("control_id", "TEXT NOT NULL DEFAULT ''"),
    ("rule_id", "TEXT NOT NULL DEFAULT ''"),
    ("status", "TEXT NOT NULL DEFAULT ''"),
    ("evidence_id", "TEXT NOT NULL DEFAULT ''"),
];

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

const EVIDENCE_CLASSIFICATIONS_SCHEMA_VERSION: u32 = 7;

const EVIDENCE_CLASSIFICATIONS_SCHEMA_SQL: &str = "
    ALTER TABLE evidence_metadata
    ADD COLUMN classification TEXT NOT NULL DEFAULT 'Unclassified';
";

const EXPORT_RECONSTRUCTION_SCHEMA_VERSION: u32 = 8;

// Version 8 uses conditional ALTERs and data backfills in
// `apply_export_reconstruction_migration`, matching migrations 3 through 5.
const EXPORT_RECONSTRUCTION_SCHEMA_SQL: &str = "";

const MIGRATION_LEDGER_SQL: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
";

const EMPTY_PACKAGED_MIGRATIONS_MESSAGE: &str =
    "no packaged migrations supplied; cannot determine current schema version";

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

const SCHEMA_VERSION_7_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("control_results", "run_id"),
    RequiredSchemaColumn::new("control_results", "control_id"),
    RequiredSchemaColumn::new("control_results", "rule_id"),
    RequiredSchemaColumn::new("control_results", "status"),
    RequiredSchemaColumn::new("control_results", "evidence_id"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("evidence_metadata", "locator"),
    RequiredSchemaColumn::new("evidence_metadata", "classification"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
    RequiredSchemaColumn::new("run_evidence_links", "run_id"),
    RequiredSchemaColumn::new("run_evidence_links", "evidence_id"),
];

const SCHEMA_VERSION_8_REQUIRED_COLUMNS: &[RequiredSchemaColumn] = &[
    RequiredSchemaColumn::new("scan_runs", "executed_at"),
    RequiredSchemaColumn::new("frameworks", "version"),
    RequiredSchemaColumn::new("control_results", "run_id"),
    RequiredSchemaColumn::new("control_results", "control_id"),
    RequiredSchemaColumn::new("control_results", "rule_id"),
    RequiredSchemaColumn::new("control_results", "status"),
    RequiredSchemaColumn::new("control_results", "evidence_id"),
    RequiredSchemaColumn::new("control_results", "framework_id"),
    RequiredSchemaColumn::new("control_results", "severity"),
    RequiredSchemaColumn::new("control_results", "weight"),
    RequiredSchemaColumn::new("control_results", "reason"),
    RequiredSchemaColumn::new("control_results", "executed_at"),
    RequiredSchemaColumn::new("control_results", "execution_metadata"),
    RequiredSchemaColumn::new("evidence_metadata", "digest"),
    RequiredSchemaColumn::new("evidence_metadata", "locator"),
    RequiredSchemaColumn::new("evidence_metadata", "classification"),
    RequiredSchemaColumn::new("compliance_gaps", "run_id"),
    RequiredSchemaColumn::new("compliance_gaps", "status"),
    RequiredSchemaColumn::new("compliance_gaps", "severity"),
    RequiredSchemaColumn::new("compliance_gaps", "control_id"),
    RequiredSchemaColumn::new("compliance_gaps", "rule_id"),
    RequiredSchemaColumn::new("run_evidence_links", "run_id"),
    RequiredSchemaColumn::new("run_evidence_links", "evidence_id"),
    RequiredSchemaColumn::new("run_evidence_links", "kind"),
    RequiredSchemaColumn::new("run_evidence_links", "digest"),
    RequiredSchemaColumn::new("run_evidence_links", "locator"),
    RequiredSchemaColumn::new("run_evidence_links", "classification"),
    RequiredSchemaColumn::new("run_framework_links", "run_id"),
    RequiredSchemaColumn::new("run_framework_links", "framework_id"),
    RequiredSchemaColumn::new("run_framework_links", "version"),
    RequiredSchemaColumn::new("run_framework_links", "source_url"),
    RequiredSchemaColumn::new("run_control_links", "run_id"),
    RequiredSchemaColumn::new("run_control_links", "framework_id"),
    RequiredSchemaColumn::new("run_control_links", "control_id"),
    RequiredSchemaColumn::new("run_control_links", "title"),
    RequiredSchemaColumn::new("run_control_links", "severity"),
    RequiredSchemaColumn::new("run_control_links", "weight"),
    RequiredSchemaColumn::new("run_control_links", "reference"),
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
    SchemaRequirements::new(
        EVIDENCE_CLASSIFICATIONS_SCHEMA_VERSION,
        SCHEMA_VERSION_7_REQUIRED_COLUMNS,
    ),
    SchemaRequirements::new(
        EXPORT_RECONSTRUCTION_SCHEMA_VERSION,
        SCHEMA_VERSION_8_REQUIRED_COLUMNS,
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

/// Persisted status-count summary for one framework in a completed run.
#[derive(Debug, PartialEq)]
pub struct ScoreSummaryRecord {
    /// Framework identifier this summary belongs to.
    framework_id: String,
    /// Number of PASS results counted for the framework in this run.
    pass_count: u32,
    /// Number of FAIL results counted for the framework in this run.
    fail_count: u32,
    /// Number of WARNING results counted for the framework in this run.
    warning_count: u32,
}

impl ScoreSummaryRecord {
    /// Returns the framework this summary belongs to.
    #[must_use]
    pub fn framework_id(&self) -> &str {
        &self.framework_id
    }

    /// Returns the number of PASS results counted for the framework.
    #[must_use]
    pub fn pass_count(&self) -> u32 {
        self.pass_count
    }

    /// Returns the number of FAIL results counted for the framework.
    #[must_use]
    pub fn fail_count(&self) -> u32 {
        self.fail_count
    }

    /// Returns the number of WARNING results counted for the framework.
    #[must_use]
    pub fn warning_count(&self) -> u32 {
        self.warning_count
    }
}

#[derive(Default)]
struct ScoreSummaryCounts {
    pass: u32,
    fail: u32,
    warning: u32,
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
    classification: String,
}

struct PersistedExportResult {
    framework_id: String,
    control_id: String,
    rule_id: String,
    status: String,
    evidence_id: String,
    severity: String,
    weight: u32,
    reason: Option<String>,
    executed_at: String,
    execution_metadata: String,
}

struct PersistedExportControl {
    framework_id: String,
    control_id: String,
    title: String,
    severity: String,
    weight: u32,
    reference: String,
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

    /// Returns the persisted confidentiality classification.
    #[must_use]
    pub fn classification(&self) -> &str {
        &self.classification
    }

    /// Returns the redaction status derived from the persisted classification.
    #[must_use]
    pub fn redaction_status(&self) -> &str {
        match Classification::from_persisted(&self.classification) {
            Some(Classification::Unclassified) => "none",
            Some(Classification::Secret | Classification::Sensitive) | None => "redacted",
        }
    }
}

fn non_local_database_target(path: &Path) -> Option<&str> {
    let target = path.to_str()?;
    let (scheme, _) = target.split_once("://")?;
    let mut bytes = scheme.bytes();
    let first = bytes.next()?;
    (first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    .then_some(target)
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
        if let Some(target) = non_local_database_target(path) {
            return Err(LocalDatabaseError::NonLocalTarget(target.to_owned()));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(LocalDatabaseError::Io)?;
        }
        let mut connection = Connection::open(path).map_err(LocalDatabaseError::Sqlite)?;
        reject_newer_schema_version(&connection, migrations)?;
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

    /// Retrieves a completed run's fixed executed-at timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read the scan run.
    pub fn completed_run_executed_at(
        &self,
        run_id: &str,
    ) -> Result<Option<String>, LocalDatabaseError> {
        self.connection
            .query_row(
                "SELECT executed_at FROM scan_runs WHERE id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Retrieves framework record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read framework records.
    pub fn framework_records_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<String>, LocalDatabaseError> {
        query_run_scoped_ids(
            &self.connection,
            "SELECT framework_id
             FROM run_framework_links
             WHERE run_id = ?1
             ORDER BY framework_id",
            run_id,
        )
    }

    /// Retrieves control record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read control records.
    pub fn control_records_for_run(&self, run_id: &str) -> Result<Vec<String>, LocalDatabaseError> {
        query_run_scoped_ids(
            &self.connection,
            "SELECT control_id
             FROM run_control_links
             WHERE run_id = ?1
             ORDER BY control_id",
            run_id,
        )
    }

    /// Retrieves control-result record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read control-result records.
    pub fn control_result_records_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<String>, LocalDatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT framework_id, control_id, rule_id
                 FROM control_results
                 WHERE run_id = ?1
                 ORDER BY framework_id, control_id, rule_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map(params![run_id], |row| {
                let framework_id = row.get::<_, String>(0)?;
                let control_id = row.get::<_, String>(1)?;
                let rule_id = row.get::<_, String>(2)?;
                Ok(format!("{framework_id}:{control_id}:{rule_id}"))
            })
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Retrieves compliance-gap record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read compliance-gap records.
    pub fn compliance_gap_records_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<String>, LocalDatabaseError> {
        let row_ids = query_run_scoped_ids(
            &self.connection,
            "SELECT id FROM compliance_gaps WHERE run_id = ?1 ORDER BY id",
            run_id,
        )?;
        Ok(row_ids
            .into_iter()
            .map(|row_id| {
                compliance_gap_identity(&row_id)
                    .map(|(_, framework_id, control_id, rule_id)| {
                        format!("{framework_id}:{control_id}:{rule_id}")
                    })
                    .unwrap_or(row_id)
            })
            .collect())
    }

    /// Retrieves evidence metadata record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read evidence metadata records.
    pub fn evidence_metadata_records_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<String>, LocalDatabaseError> {
        query_run_scoped_ids(
            &self.connection,
            "SELECT evidence_metadata.id
             FROM evidence_metadata
             INNER JOIN run_evidence_links
               ON run_evidence_links.evidence_id = evidence_metadata.id
             WHERE run_evidence_links.run_id = ?1
             ORDER BY evidence_metadata.id",
            run_id,
        )
    }

    /// Retrieves score-summary record ids for a run.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read score-summary records.
    pub fn score_summary_records_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<String>, LocalDatabaseError> {
        ensure_score_summary_schema(&self.connection)?;
        query_run_scoped_ids(
            &self.connection,
            "SELECT framework_id
             FROM score_summaries
             WHERE run_id = ?1
             ORDER BY framework_id",
            run_id,
        )
    }

    /// Retrieves score summaries for a completed run in stable framework order.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` cannot read the score summaries.
    pub fn score_summaries_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<ScoreSummaryRecord>, LocalDatabaseError> {
        ensure_score_summary_schema(&self.connection)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT framework_id, pass_count, fail_count, warning_count
                 FROM score_summaries
                 WHERE run_id = ?1
                 ORDER BY framework_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok(ScoreSummaryRecord {
                    framework_id: row.get(0)?,
                    pass_count: row.get(1)?,
                    fail_count: row.get(2)?,
                    warning_count: row.get(3)?,
                })
            })
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
                "SELECT
                   id,
                   digest,
                   locator,
                   classification
                 FROM evidence_metadata
                 WHERE id = ?1
                 ORDER BY id"
            }
            EvidenceLookup::Digest => {
                "SELECT
                   id,
                   digest,
                   locator,
                   classification
                 FROM evidence_metadata
                 WHERE digest = ?1
                 ORDER BY id"
            }
            EvidenceLookup::Control => {
                "SELECT DISTINCT
                   evidence_metadata.id,
                   evidence_metadata.digest,
                   evidence_metadata.locator,
                   evidence_metadata.classification
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
                    classification: row.get("classification")?,
                })
            })
            .map_err(LocalDatabaseError::Sqlite)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)
    }

    /// Exports one persisted run through an existing artifact format.
    ///
    /// # Errors
    ///
    /// Returns an error if the run is missing, `SQLite` metadata cannot be read,
    /// the format is unsupported, or the PDF renderer cannot write the artifact.
    pub fn export_run(
        &self,
        format: &str,
        run_id: &str,
        signing_seed: &[u8; 32],
    ) -> Result<Vec<u8>, LocalDatabaseError> {
        let corpus = self.reconstruct_export_corpus(run_id)?;
        match format {
            "PDF" => crate::report::export(&corpus).map_err(LocalDatabaseError::Export),
            "SpreadsheetML" => Ok(crate::matrix::export(&corpus).into_bytes()),
            "signed JSON" => Ok(crate::signed_json::export(&corpus, signing_seed).into_bytes()),
            other => Err(LocalDatabaseError::UnsupportedExportFormat(
                other.to_owned(),
            )),
        }
    }

    fn reconstruct_export_corpus(&self, run_id: &str) -> Result<Corpus, LocalDatabaseError> {
        let executed_at = match self.connection.query_row(
            "SELECT executed_at FROM scan_runs WHERE id = ?1",
            params![run_id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(executed_at) => executed_at,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(LocalDatabaseError::MissingRun(run_id.to_owned()));
            }
            Err(error) => return Err(LocalDatabaseError::Sqlite(error)),
        };

        let frameworks = export_framework_rows(&self.connection, run_id)?;
        let mut corpus = Corpus::new(&executed_at).with_run_id(run_id);
        for (id, version, source_url) in frameworks {
            corpus = corpus.with_framework(id, version, source_url);
        }

        let results = export_result_rows(&self.connection, run_id)?;

        let controls = export_control_rows(&self.connection, run_id)?;
        for control in controls {
            corpus = corpus.with_control(
                control.framework_id,
                control.control_id,
                control.title,
                control.severity,
                control.weight,
                control.reference,
            );
        }

        for persisted in results {
            let result = reconstruct_control_result(&persisted, &executed_at)?;
            corpus = if persisted.framework_id.is_empty() {
                corpus.with_unscoped_control_result(result)
            } else {
                corpus.with_control_result(persisted.framework_id, result)
            };
        }

        let evidence = export_evidence_rows(&self.connection, run_id)?;
        for (id, kind, digest, locator, classification) in evidence {
            corpus = match Classification::from_persisted(&classification)
                .unwrap_or(Classification::Secret)
            {
                Classification::Unclassified => {
                    corpus.with_evidence_digest(id, kind, locator, digest)
                }
                Classification::Sensitive => corpus.with_classified_evidence(
                    id,
                    kind,
                    locator,
                    Classification::Sensitive,
                    digest,
                ),
                Classification::Secret => corpus.with_classified_evidence(
                    id,
                    kind,
                    locator,
                    Classification::Secret,
                    digest,
                ),
            };
        }
        Ok(corpus)
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
        validate_linked_evidence(store, metadata)
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
                "SELECT evidence_id, digest, locator, classification
                 FROM run_evidence_links
                 WHERE run_id = ?1
                 ORDER BY evidence_id",
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        let evidence = statement
            .query_map(params![run_id], |row| {
                Ok(LocalDatabaseEvidence {
                    id: row.get(0)?,
                    digest: row.get(1)?,
                    locator: row.get(2)?,
                    classification: row.get(3)?,
                })
            })
            .map_err(LocalDatabaseError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(LocalDatabaseError::Sqlite)?;

        for metadata in evidence {
            validate_linked_evidence(store, metadata)?;
        }
        Ok(())
    }

    /// Writes a completed scan corpus into the local database.
    ///
    /// # Errors
    ///
    /// Returns an error if the corpus has no run id or `SQLite` cannot start,
    /// populate, or commit the write transaction.
    pub fn write_completed_corpus(&mut self, corpus: &Corpus) -> Result<(), LocalDatabaseError> {
        let run_id = corpus.run_id();
        if run_id.trim().is_empty() {
            return Err(LocalDatabaseError::Schema(
                "completed corpus run_id cannot be empty".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(LocalDatabaseError::Sqlite)?;
        let scoped_results = corpus.scoped_results();

        write_run_catalog(&transaction, run_id, corpus)?;
        clear_run_outcomes(&transaction, run_id)?;
        write_score_summaries(&transaction, corpus)?;

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
                       evidence_id,
                       framework_id,
                       severity,
                       weight,
                       reason,
                       executed_at,
                       execution_metadata
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(id) DO UPDATE SET
                       run_id = COALESCE(NULLIF(control_results.run_id, ''), excluded.run_id),
                       status = excluded.status,
                       evidence_id = excluded.evidence_id,
                       framework_id = excluded.framework_id,
                       severity = excluded.severity,
                       weight = excluded.weight,
                       reason = excluded.reason,
                       executed_at = excluded.executed_at,
                       execution_metadata = excluded.execution_metadata",
                    params![
                        result_id,
                        run_id,
                        result.control_id(),
                        result.rule_id(),
                        result.status().label(),
                        evidence_id,
                        framework_id.unwrap_or_default(),
                        result.severity(),
                        result.weight(),
                        result.reason(),
                        result.executed_at(),
                        result.execution_metadata()
                    ],
                )
                .map_err(LocalDatabaseError::Sqlite)?;
        }

        write_gap_rows(&transaction, run_id, &scoped_results)?;

        write_evidence_rows(&transaction, run_id, corpus).map_err(LocalDatabaseError::Sqlite)?;

        transaction.commit().map_err(LocalDatabaseError::Sqlite)
    }
}

fn write_score_summaries(
    transaction: &Transaction<'_>,
    corpus: &Corpus,
) -> Result<(), LocalDatabaseError> {
    add_missing_score_summary_columns(transaction)?;
    let run_id = corpus.run_id();
    transaction
        .execute(
            "DELETE FROM score_summaries
             WHERE run_id = ?1",
            [run_id],
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    for (framework_id, counts) in score_summary_counts(corpus) {
        transaction
            .execute(
                "INSERT OR REPLACE INTO score_summaries(
                   id,
                   run_id,
                   framework_id,
                   pass_count,
                   fail_count,
                   warning_count
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    score_summary_row_id(run_id, &framework_id),
                    run_id,
                    framework_id,
                    counts.pass,
                    counts.fail,
                    counts.warning,
                ],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    Ok(())
}

fn score_summary_row_id(run_id: &str, framework_id: &str) -> String {
    // Length-prefix both identifiers so delimiters inside either value cannot
    // make two distinct (run, framework) pairs produce the same row id.
    format!(
        "{}:{run_id}:{}:{framework_id}",
        run_id.len(),
        framework_id.len()
    )
}

fn score_summary_counts(corpus: &Corpus) -> std::collections::BTreeMap<String, ScoreSummaryCounts> {
    let mut summaries = std::collections::BTreeMap::new();
    for (framework_id, result) in corpus.scoped_results() {
        let Some(framework_id) = framework_id.filter(|framework_id| !framework_id.is_empty())
        else {
            continue;
        };
        let summary: &mut ScoreSummaryCounts =
            summaries.entry(framework_id.to_owned()).or_default();
        match result.status() {
            Status::Pass => summary.pass += 1,
            Status::Fail => summary.fail += 1,
            Status::Warning => summary.warning += 1,
            Status::Skipped | Status::Error => {}
        }
    }
    summaries
}

fn ensure_score_summary_schema(connection: &Connection) -> Result<(), LocalDatabaseError> {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(LocalDatabaseError::Sqlite)?;
    let transaction =
        Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)
            .map_err(LocalDatabaseError::Sqlite)?;
    add_missing_score_summary_columns(&transaction)?;
    transaction.commit().map_err(LocalDatabaseError::Sqlite)
}

fn add_missing_score_summary_columns(connection: &Connection) -> Result<(), LocalDatabaseError> {
    if !schema_column_exists(connection, "score_summaries", "run_id")? {
        connection
            .execute(
                "ALTER TABLE score_summaries
                 ADD COLUMN run_id TEXT",
                [],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    if !schema_column_exists(connection, "score_summaries", "framework_id")? {
        connection
            .execute(
                "ALTER TABLE score_summaries
                 ADD COLUMN framework_id TEXT",
                [],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    if !schema_column_exists(connection, "score_summaries", "pass_count")? {
        connection
            .execute(
                "ALTER TABLE score_summaries
                 ADD COLUMN pass_count INTEGER",
                [],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    if !schema_column_exists(connection, "score_summaries", "fail_count")? {
        connection
            .execute(
                "ALTER TABLE score_summaries
                 ADD COLUMN fail_count INTEGER",
                [],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    if !schema_column_exists(connection, "score_summaries", "warning_count")? {
        connection
            .execute(
                "ALTER TABLE score_summaries
                 ADD COLUMN warning_count INTEGER",
                [],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    Ok(())
}

fn query_run_scoped_ids(
    connection: &Connection,
    sql: &str,
    run_id: &str,
) -> Result<Vec<String>, LocalDatabaseError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(LocalDatabaseError::Sqlite)?;
    let rows = statement
        .query_map(params![run_id], |row| row.get::<_, String>(0))
        .map_err(LocalDatabaseError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LocalDatabaseError::Sqlite)
}

fn validate_linked_evidence(
    store: &EvidenceStore,
    metadata: LocalDatabaseEvidence,
) -> Result<Option<LocalDatabaseEvidence>, LocalDatabaseError> {
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
        return Err(LocalDatabaseError::MissingEvidence {
            evidence_id: metadata.id().to_owned(),
            expected: metadata.digest().to_owned(),
        });
    };
    Err(LocalDatabaseError::IntegrityMismatch {
        evidence_id: metadata.id().to_owned(),
        expected: metadata.digest().to_owned(),
        actual: record.content_hash().to_owned(),
    })
}

fn write_run_catalog(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    corpus: &Corpus,
) -> Result<(), LocalDatabaseError> {
    transaction
        .execute(
            "INSERT INTO scan_runs(id, executed_at) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
               executed_at = COALESCE(NULLIF(excluded.executed_at, ''), scan_runs.executed_at)",
            params![run_id, corpus.executed_at()],
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    transaction
        .execute(
            "DELETE FROM run_framework_links WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    transaction
        .execute(
            "DELETE FROM run_control_links WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(LocalDatabaseError::Sqlite)?;

    for (framework_id, version, source_url) in corpus.frameworks() {
        transaction
            .execute(
                "INSERT INTO frameworks(id, version) VALUES (?1, ?2)
                 ON CONFLICT(id) DO NOTHING",
                params![framework_id, version],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        transaction
            .execute(
                "INSERT INTO run_framework_links(
                   run_id, framework_id, version, source_url
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(run_id, framework_id) DO UPDATE SET
                   version = excluded.version,
                   source_url = excluded.source_url",
                params![run_id, framework_id, version, source_url],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }

    for control in corpus.control_records() {
        transaction
            .execute(
                "INSERT INTO controls(id) VALUES (?1)
                 ON CONFLICT(id) DO NOTHING",
                params![control.id],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
        transaction
            .execute(
                "INSERT INTO run_control_links(
                   run_id,
                   framework_id,
                   control_id,
                   title,
                   severity,
                   weight,
                   reference
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(run_id, framework_id, control_id) DO UPDATE SET
                   title = excluded.title,
                   severity = excluded.severity,
                   weight = excluded.weight,
                   reference = excluded.reference",
                params![
                    run_id,
                    control.framework_id,
                    control.id,
                    control.title,
                    control.severity,
                    control.weight,
                    control.reference
                ],
            )
            .map_err(LocalDatabaseError::Sqlite)?;
    }
    Ok(())
}

fn clear_run_outcomes(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
) -> Result<(), LocalDatabaseError> {
    transaction
        .execute(
            "DELETE FROM control_results WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    transaction
        .execute(
            "DELETE FROM compliance_gaps WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    Ok(())
}

fn export_framework_rows(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<(String, String, String)>, LocalDatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT framework_id, version, source_url
             FROM run_framework_links
             WHERE run_id = ?1
             ORDER BY framework_id",
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(LocalDatabaseError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LocalDatabaseError::Sqlite)
}

fn export_result_rows(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<PersistedExportResult>, LocalDatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT framework_id,
                    control_id,
                    rule_id,
                    status,
                    evidence_id,
                    severity,
                    weight,
                    reason,
                    executed_at,
                    execution_metadata
             FROM control_results
             WHERE run_id = ?1
             ORDER BY control_id, rule_id, framework_id",
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok(PersistedExportResult {
                framework_id: row.get(0)?,
                control_id: row.get(1)?,
                rule_id: row.get(2)?,
                status: row.get(3)?,
                evidence_id: row.get(4)?,
                severity: row.get(5)?,
                weight: row.get(6)?,
                reason: row.get(7)?,
                executed_at: row.get(8)?,
                execution_metadata: row.get(9)?,
            })
        })
        .map_err(LocalDatabaseError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LocalDatabaseError::Sqlite)
}

fn export_control_rows(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<PersistedExportControl>, LocalDatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT framework_id,
                    control_id,
                    title,
                    severity,
                    weight,
                    reference
             FROM run_control_links
             WHERE run_id = ?1
             ORDER BY framework_id, control_id",
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok(PersistedExportControl {
                framework_id: row.get(0)?,
                control_id: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                weight: row.get(4)?,
                reference: row.get(5)?,
            })
        })
        .map_err(LocalDatabaseError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LocalDatabaseError::Sqlite)
}

type ExportEvidenceRow = (String, String, String, String, String);

fn export_evidence_rows(
    connection: &Connection,
    run_id: &str,
) -> Result<Vec<ExportEvidenceRow>, LocalDatabaseError> {
    let mut statement = connection
        .prepare(
            "SELECT evidence_id, kind, digest, locator, classification
             FROM run_evidence_links
             WHERE run_id = ?1
             ORDER BY evidence_id",
        )
        .map_err(LocalDatabaseError::Sqlite)?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(LocalDatabaseError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(LocalDatabaseError::Sqlite)
}

fn reconstruct_control_result(
    persisted: &PersistedExportResult,
    run_executed_at: &str,
) -> Result<ControlResult, LocalDatabaseError> {
    let status = persisted_status(&persisted.status)?;
    let executed_at = if persisted.executed_at.is_empty() {
        run_executed_at
    } else {
        &persisted.executed_at
    };
    if executed_at.is_empty() {
        return Err(LocalDatabaseError::Schema(format!(
            "persisted result {}:{} execution timestamp is missing",
            persisted.control_id, persisted.rule_id
        )));
    }
    let evidence_refs = if persisted.evidence_id.is_empty() {
        Vec::new()
    } else {
        vec![persisted.evidence_id.as_str()]
    };
    let mut builder = ControlResult::builder()
        .control_id(&persisted.control_id)
        .rule_id(&persisted.rule_id)
        .status(status)
        .severity(&persisted.severity)
        .weight(persisted.weight)
        .evidence_refs(evidence_refs)
        .executed_at(executed_at)
        .execution_metadata(&persisted.execution_metadata);
    if let Some(reason) = persisted
        .reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
    {
        builder = builder.reason(reason);
    } else if status != Status::Pass {
        builder = builder.reason(status.description());
    }
    builder.build().map_err(|error| {
        LocalDatabaseError::Schema(format!(
            "persisted result {}:{} is invalid: {error}",
            persisted.control_id, persisted.rule_id
        ))
    })
}

fn persisted_status(label: &str) -> Result<Status, LocalDatabaseError> {
    match label {
        "PASS" => Ok(Status::Pass),
        "FAIL" => Ok(Status::Fail),
        "WARNING" => Ok(Status::Warning),
        "SKIPPED" => Ok(Status::Skipped),
        "ERROR" => Ok(Status::Error),
        _ => Err(LocalDatabaseError::Schema(format!(
            "persisted control result has unsupported status {label:?}"
        ))),
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
    let has_legacy_run_id =
        transaction_schema_column_exists(transaction, "evidence_metadata", "run_id")?;
    for evidence in corpus.evidence_records() {
        if has_legacy_run_id {
            transaction.execute(
                // Legacy rewrites preserve integrity-backed metadata they do not carry.
                "INSERT INTO evidence_metadata(
                   id, run_id, digest, locator, classification
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                   -- Keep the first legacy owner; current per-run ownership is
                   -- represented by run_evidence_links.
                   run_id = evidence_metadata.run_id,
                   digest = COALESCE(NULLIF(excluded.digest, ''), evidence_metadata.digest),
                   locator = CASE
                     WHEN evidence_metadata.locator = '' THEN excluded.locator
                     ELSE evidence_metadata.locator
                   END,
                   classification = CASE
                     WHEN excluded.digest = '' THEN evidence_metadata.classification
                     ELSE excluded.classification
                   END",
                params![
                    evidence.id,
                    run_id,
                    evidence.integrity,
                    evidence.locator,
                    evidence.classification
                ],
            )?;
        } else {
            transaction.execute(
                // Legacy rewrites preserve integrity-backed metadata they do not carry.
                "INSERT INTO evidence_metadata(id, digest, locator, classification)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                   digest = COALESCE(NULLIF(excluded.digest, ''), evidence_metadata.digest),
                   locator = CASE
                     WHEN evidence_metadata.locator = '' THEN excluded.locator
                     ELSE evidence_metadata.locator
                   END,
                   classification = CASE
                     WHEN excluded.digest = '' THEN evidence_metadata.classification
                     ELSE excluded.classification
                   END",
                params![
                    evidence.id,
                    evidence.integrity,
                    evidence.locator,
                    evidence.classification
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO run_evidence_links(
               run_id, evidence_id, kind, digest, locator, classification
             )
             SELECT
               ?1,
               ?2,
               ?3,
               CASE WHEN ?4 = '' THEN digest ELSE ?4 END,
               ?5,
               CASE WHEN ?4 = '' THEN classification ELSE ?6 END
             FROM evidence_metadata
             WHERE id = ?2
             ON CONFLICT(run_id, evidence_id) DO UPDATE SET
               kind = excluded.kind,
               digest = excluded.digest,
               locator = excluded.locator,
               classification = excluded.classification",
            params![
                run_id,
                evidence.id,
                evidence.kind,
                evidence.integrity,
                evidence.locator,
                evidence.classification
            ],
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

fn reject_newer_schema_version(
    connection: &Connection,
    migrations: &[PackagedMigration],
) -> Result<(), LocalDatabaseError> {
    let schema_version = connection_schema_version(connection)?;
    let packaged_schema_version = current_packaged_schema_version(migrations)?;
    if schema_version > packaged_schema_version {
        return Err(LocalDatabaseError::Schema(format!(
            "unsupported newer schema version {schema_version}; packaged current schema version is {packaged_schema_version}"
        )));
    }

    Ok(())
}

fn current_packaged_schema_version(
    migrations: &[PackagedMigration],
) -> Result<u32, LocalDatabaseError> {
    let mut previous_version = None;
    for migration in migrations {
        if let Some(version) = previous_version {
            match migration.version.cmp(&version) {
                std::cmp::Ordering::Less => {
                    return Err(LocalDatabaseError::Schema(format!(
                        "packaged migration version {} appears after version {version}; migrations must be ordered by ascending version",
                        migration.version
                    )));
                }
                std::cmp::Ordering::Equal => {
                    return Err(LocalDatabaseError::Schema(format!(
                        "duplicate packaged migration version {version}"
                    )));
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        previous_version = Some(migration.version);
    }

    previous_version
        .ok_or_else(|| LocalDatabaseError::Schema(EMPTY_PACKAGED_MIGRATIONS_MESSAGE.to_owned()))
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

fn schema_has_required_columns(
    connection: &Connection,
    required_columns: &[RequiredSchemaColumn],
) -> Result<bool, LocalDatabaseError> {
    for required_column in required_columns {
        if !schema_column_exists(
            connection,
            required_column.table_name,
            required_column.column_name,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
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

    if migration.version == EVIDENCE_CLASSIFICATIONS_SCHEMA_VERSION
        && migration.name == "0007-evidence-classifications"
        && migration.sql == EVIDENCE_CLASSIFICATIONS_SCHEMA_SQL
    {
        let schema_version = connection_schema_version(connection)?;
        return Ok(
            (INITIAL_SCHEMA_VERSION..EVIDENCE_CLASSIFICATIONS_SCHEMA_VERSION)
                .contains(&schema_version)
                && migration_is_applied(connection, schema_version)?
                && schema_has_required_columns(connection, SCHEMA_VERSION_6_REQUIRED_COLUMNS)?
                && !schema_column_exists(connection, "evidence_metadata", "classification")?,
        );
    }

    if migration.version == EXPORT_RECONSTRUCTION_SCHEMA_VERSION
        && migration.name == "0008-export-reconstruction"
        && migration.sql == EXPORT_RECONSTRUCTION_SCHEMA_SQL
    {
        let schema_version = connection_schema_version(connection)?;
        return Ok(
            (INITIAL_SCHEMA_VERSION..EXPORT_RECONSTRUCTION_SCHEMA_VERSION)
                .contains(&schema_version)
                && migration_is_applied(connection, schema_version)?
                && schema_has_required_columns(connection, SCHEMA_VERSION_7_REQUIRED_COLUMNS)?
                && !schema_has_required_columns(connection, SCHEMA_VERSION_8_REQUIRED_COLUMNS)?,
        );
    }

    Ok(true)
}

fn apply_packaged_migration(
    connection: &mut Connection,
    migration: &PackagedMigration,
) -> Result<(), LocalDatabaseError> {
    if let Some(operation) = destructive_migration_operation(migration.sql) {
        return Err(LocalDatabaseError::DestructiveMigration {
            name: migration.name.to_owned(),
            operation,
        });
    }

    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(LocalDatabaseError::Sqlite)?;
    if migration_is_applied(&transaction, migration.version)? {
        return transaction
            .commit()
            .map_err(|source| migration_error(migration, source));
    }
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
    } else if migration.version == EXPORT_RECONSTRUCTION_SCHEMA_VERSION
        && migration.name == "0008-export-reconstruction"
        && migration.sql == EXPORT_RECONSTRUCTION_SCHEMA_SQL
    {
        apply_export_reconstruction_migration(&transaction)
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

fn destructive_migration_operation(sql: &str) -> Option<String> {
    let tokens = sql_tokens(sql);
    let mut index = 0;

    while index + 2 < tokens.len() {
        if tokens[index].eq_ignore_ascii_case("DROP")
            && tokens[index + 1].eq_ignore_ascii_case("TABLE")
        {
            let table_index = if tokens
                .get(index + 2)
                .is_some_and(|token| token.eq_ignore_ascii_case("IF"))
                && tokens
                    .get(index + 3)
                    .is_some_and(|token| token.eq_ignore_ascii_case("EXISTS"))
            {
                index + 4
            } else {
                index + 2
            };

            if let Some((table_name, _)) = sql_table_name(&tokens, table_index) {
                if PERSISTED_CORPUS_TABLES.contains(&table_name.as_str()) {
                    return Some(format!("DROP TABLE {table_name}"));
                }
            }
        } else if tokens[index].eq_ignore_ascii_case("ALTER")
            && tokens[index + 1].eq_ignore_ascii_case("TABLE")
        {
            let Some((table_name, operation_index)) = sql_table_name(&tokens, index + 2) else {
                index += 1;
                continue;
            };
            if PERSISTED_CORPUS_TABLES.contains(&table_name.as_str()) {
                let drops_column = tokens
                    .get(operation_index)
                    .is_some_and(|token| token.eq_ignore_ascii_case("DROP"))
                    && tokens
                        .get(operation_index + 1)
                        .is_some_and(|token| !token.eq_ignore_ascii_case("CONSTRAINT"));
                if drops_column {
                    return Some(format!("ALTER TABLE {table_name} DROP COLUMN"));
                }
                let renames_table_or_column = tokens
                    .get(operation_index)
                    .is_some_and(|token| token.eq_ignore_ascii_case("RENAME"));
                if renames_table_or_column {
                    return Some(format!("ALTER TABLE {table_name} RENAME"));
                }
            }
        }

        index += 1;
    }

    None
}

fn sql_table_name(tokens: &[String], table_index: usize) -> Option<(String, usize)> {
    let schema_or_table = tokens.get(table_index)?;
    if tokens
        .get(table_index + 1)
        .is_some_and(|token| token == ".")
    {
        return tokens
            .get(table_index + 2)
            .map(|table_name| (canonical_sql_identifier(table_name), table_index + 3));
    }

    Some((canonical_sql_identifier(schema_or_table), table_index + 1))
}

fn sql_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut characters = sql.chars().peekable();

    while let Some(character) = characters.next() {
        if character == '-' && characters.peek() == Some(&'-') {
            characters.next();
            push_sql_token(&mut tokens, &mut token);
            skip_line_comment(&mut characters);
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            push_sql_token(&mut tokens, &mut token);
            skip_block_comment(&mut characters);
        } else if character == '\'' {
            push_sql_token(&mut tokens, &mut token);
            tokens.push(format!(
                "'{}'",
                collect_quoted_identifier(&mut characters, '\'')
            ));
        } else if character == '"' {
            push_sql_token(&mut tokens, &mut token);
            tokens.push(collect_quoted_identifier(&mut characters, '"'));
        } else if character == '`' {
            push_sql_token(&mut tokens, &mut token);
            tokens.push(collect_quoted_identifier(&mut characters, '`'));
        } else if character == '[' {
            push_sql_token(&mut tokens, &mut token);
            tokens.push(collect_quoted_identifier(&mut characters, ']'));
        } else if character == '.' {
            push_sql_token(&mut tokens, &mut token);
            tokens.push(".".to_owned());
        } else if is_sql_token_character(character) {
            token.push(character);
        } else {
            push_sql_token(&mut tokens, &mut token);
        }
    }

    push_sql_token(&mut tokens, &mut token);
    tokens
}

fn push_sql_token(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

fn skip_line_comment(characters: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for character in characters.by_ref() {
        if character == '\n' {
            break;
        }
    }
}

fn skip_block_comment(characters: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(character) = characters.next() {
        if character == '*' && characters.peek() == Some(&'/') {
            characters.next();
            break;
        }
    }
}

fn collect_quoted_identifier(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    terminator: char,
) -> String {
    let mut identifier = String::new();

    while let Some(character) = characters.next() {
        if character == terminator {
            if matches!(terminator, '\'' | '"' | '`') && characters.peek() == Some(&terminator) {
                characters.next();
                identifier.push(terminator);
            } else {
                break;
            }
        } else {
            identifier.push(character);
        }
    }

    identifier
}

fn is_sql_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn canonical_sql_identifier(identifier: &str) -> String {
    identifier
        .trim_matches(|character| matches!(character, '"' | '\'' | '`' | '[' | ']'))
        .to_ascii_lowercase()
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
    // Recover fields encoded by later length-prefixed ids. Schema v1 exposed no
    // writer, so truly opaque v1 ids are preserved with empty metadata instead
    // of inventing values; new corpus writes create fully populated rows.
    for &(column_name, definition) in CONTROL_RESULT_QUERY_FILTER_COLUMNS {
        add_column_if_missing(transaction, "control_results", column_name, definition)?;
    }
    if transaction_schema_column_exists(transaction, "evidence_metadata", "id")? {
        add_column_if_missing(
            transaction,
            "evidence_metadata",
            "locator",
            "TEXT NOT NULL DEFAULT ''",
        )?;
    }

    backfill_control_result_identity_fields(transaction)?;
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

fn apply_export_reconstruction_migration(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    ensure_export_reconstruction_schema(transaction)?;
    backfill_export_catalog_links(transaction)?;
    backfill_export_result_metadata(transaction)?;
    backfill_run_snapshot_metadata(transaction)
}

fn ensure_export_reconstruction_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    add_column_if_missing(
        transaction,
        "scan_runs",
        "executed_at",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    for (column_name, definition) in [
        ("framework_id", "TEXT NOT NULL DEFAULT ''"),
        ("severity", "TEXT NOT NULL DEFAULT ''"),
        ("weight", "INTEGER NOT NULL DEFAULT 0"),
        ("reason", "TEXT"),
        ("executed_at", "TEXT NOT NULL DEFAULT ''"),
        ("execution_metadata", "TEXT NOT NULL DEFAULT ''"),
    ] {
        add_column_if_missing(transaction, "control_results", column_name, definition)?;
    }
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS run_framework_links (
           run_id TEXT NOT NULL,
           framework_id TEXT NOT NULL,
           version TEXT NOT NULL DEFAULT '',
           source_url TEXT NOT NULL DEFAULT '',
           PRIMARY KEY (run_id, framework_id)
         );
         CREATE TABLE IF NOT EXISTS run_control_links (
           run_id TEXT NOT NULL,
           framework_id TEXT NOT NULL,
           control_id TEXT NOT NULL,
           title TEXT NOT NULL DEFAULT '',
           severity TEXT NOT NULL DEFAULT '',
           weight INTEGER NOT NULL DEFAULT 0,
           reference TEXT NOT NULL DEFAULT '',
           PRIMARY KEY (run_id, framework_id, control_id)
         );",
    )?;
    for (column_name, definition) in [
        ("kind", "TEXT NOT NULL DEFAULT ''"),
        ("digest", "TEXT NOT NULL DEFAULT ''"),
        ("locator", "TEXT NOT NULL DEFAULT ''"),
        ("classification", "TEXT NOT NULL DEFAULT 'Unclassified'"),
    ] {
        add_column_if_missing(transaction, "run_evidence_links", column_name, definition)?;
    }
    for (table_name, columns) in [
        (
            "run_framework_links",
            &[
                ("version", "TEXT NOT NULL DEFAULT ''"),
                ("source_url", "TEXT NOT NULL DEFAULT ''"),
            ][..],
        ),
        (
            "run_control_links",
            &[
                ("title", "TEXT NOT NULL DEFAULT ''"),
                ("severity", "TEXT NOT NULL DEFAULT ''"),
                ("weight", "INTEGER NOT NULL DEFAULT 0"),
                ("reference", "TEXT NOT NULL DEFAULT ''"),
            ][..],
        ),
    ] {
        for &(column_name, definition) in columns {
            add_column_if_missing(transaction, table_name, column_name, definition)?;
        }
    }
    Ok(())
}

fn backfill_export_catalog_links(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let persisted_results = {
        let mut statement = transaction.prepare(
            "SELECT id, run_id, control_id
             FROM control_results
             ORDER BY id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (row_id, persisted_run_id, persisted_control_id) in persisted_results {
        let Some((encoded_run_id, framework_id, encoded_control_id, _)) =
            control_result_identity(&row_id)
        else {
            continue;
        };
        let run_id = if persisted_run_id.is_empty() {
            encoded_run_id
        } else {
            &persisted_run_id
        };
        let control_id = if persisted_control_id.is_empty() {
            encoded_control_id
        } else {
            &persisted_control_id
        };
        transaction.execute(
            "UPDATE control_results
             SET framework_id = ?1
             WHERE id = ?2 AND framework_id = ''",
            params![framework_id, row_id],
        )?;
        if !framework_id.is_empty() {
            transaction.execute(
                "INSERT OR IGNORE INTO run_framework_links(run_id, framework_id)
                 VALUES (?1, ?2)",
                params![run_id, framework_id],
            )?;
        }
        transaction.execute(
            "INSERT OR IGNORE INTO run_control_links(run_id, framework_id, control_id)
             VALUES (?1, ?2, ?3)",
            params![run_id, framework_id, control_id],
        )?;
    }

    backfill_single_run_catalog_links(transaction)
}

fn backfill_single_run_catalog_links(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    let run_ids = {
        let mut statement = transaction.prepare("SELECT id FROM scan_runs ORDER BY id")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if let [run_id] = run_ids.as_slice() {
        transaction.execute(
            "INSERT OR IGNORE INTO run_framework_links(run_id, framework_id)
             SELECT ?1, id FROM frameworks",
            params![run_id],
        )?;
        let framework_ids = {
            let mut statement = transaction.prepare("SELECT id FROM frameworks ORDER BY id")?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if let [framework_id] = framework_ids.as_slice() {
            transaction.execute(
                "INSERT OR IGNORE INTO run_control_links(run_id, framework_id, control_id)
                 SELECT ?1, ?2, id FROM controls",
                params![run_id, framework_id],
            )?;
        }
    }
    Ok(())
}

fn backfill_run_snapshot_metadata(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute(
        "UPDATE run_framework_links
         SET version = COALESCE(
           (SELECT frameworks.version
            FROM frameworks
            WHERE frameworks.id = run_framework_links.framework_id),
           version
         )",
        [],
    )?;
    transaction.execute(
        "UPDATE run_control_links
         SET severity = COALESCE(
               (SELECT control_results.severity
                FROM control_results
                WHERE control_results.run_id = run_control_links.run_id
                  AND control_results.framework_id = run_control_links.framework_id
                  AND control_results.control_id = run_control_links.control_id
                  AND control_results.severity <> ''
                ORDER BY control_results.rule_id
                LIMIT 1),
               severity
             ),
             weight = COALESCE(
               (SELECT control_results.weight
                FROM control_results
                WHERE control_results.run_id = run_control_links.run_id
                  AND control_results.framework_id = run_control_links.framework_id
                  AND control_results.control_id = run_control_links.control_id
                ORDER BY control_results.rule_id
                LIMIT 1),
               weight
             )",
        [],
    )?;
    transaction.execute(
        "UPDATE run_evidence_links
         SET digest = COALESCE(
               (SELECT evidence_metadata.digest
                FROM evidence_metadata
                WHERE evidence_metadata.id = run_evidence_links.evidence_id),
               digest
             ),
             locator = COALESCE(
               (SELECT evidence_metadata.locator
                FROM evidence_metadata
                WHERE evidence_metadata.id = run_evidence_links.evidence_id),
               locator
             ),
             classification = COALESCE(
               (SELECT evidence_metadata.classification
                FROM evidence_metadata
                WHERE evidence_metadata.id = run_evidence_links.evidence_id),
               classification
             )",
        [],
    )?;
    Ok(())
}

fn backfill_export_result_metadata(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    transaction.execute(
        "UPDATE control_results
         SET severity = COALESCE(
           (
             SELECT compliance_gaps.severity
             FROM compliance_gaps
             WHERE compliance_gaps.run_id = control_results.run_id
               AND compliance_gaps.control_id = control_results.control_id
               AND compliance_gaps.rule_id = control_results.rule_id
             ORDER BY compliance_gaps.id
             LIMIT 1
           ),
           severity
         )
         WHERE severity = ''",
        [],
    )?;
    transaction.execute(
        "UPDATE control_results
         SET executed_at = COALESCE(
           (SELECT scan_runs.executed_at FROM scan_runs WHERE scan_runs.id = control_results.run_id),
           executed_at
         )
         WHERE executed_at = ''",
        [],
    )?;
    Ok(())
}

fn add_column_if_missing(
    transaction: &rusqlite::Transaction<'_>,
    table_name: &str,
    column_name: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    if !transaction_schema_column_exists(transaction, table_name, column_name)? {
        transaction.execute(
            &format!("ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"),
            [],
        )?;
    }
    Ok(())
}

fn backfill_control_result_identity_fields(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    let mut statement = transaction.prepare("SELECT id FROM control_results")?;
    let row_ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for row_id in row_ids {
        if let Some((run_id, _, control_id, rule_id)) = control_result_identity(&row_id) {
            transaction.execute(
                "UPDATE control_results
                 SET run_id = COALESCE(NULLIF(run_id, ''), ?1),
                     control_id = COALESCE(NULLIF(control_id, ''), ?2),
                     rule_id = COALESCE(NULLIF(rule_id, ''), ?3)
                 WHERE id = ?4",
                params![run_id, control_id, rule_id, row_id],
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
fn control_result_run_id(row_id: &str) -> Option<&str> {
    control_result_identity(row_id).map(|(run_id, _, _, _)| run_id)
}

fn control_result_identity(row_id: &str) -> Option<(&str, &str, &str, &str)> {
    let (run_id, remainder) = take_length_prefixed_field(row_id)?;
    let (framework_id, remainder) = take_length_prefixed_field(remainder)?;
    let (control_id, rule_id) = take_length_prefixed_field(remainder)?;
    (!run_id.is_empty() && !control_id.is_empty() && !rule_id.is_empty()).then_some((
        run_id,
        framework_id,
        control_id,
        rule_id,
    ))
}

fn compliance_gap_identity(row_id: &str) -> Option<(&str, &str, &str, &str)> {
    let (run_id, remainder) = take_length_prefixed_field(row_id)?;
    let (framework_id, remainder) = take_length_prefixed_field(remainder)?;
    let (control_id, remainder) = take_length_prefixed_field(remainder)?;
    let (rule_id_length, rule_id) = remainder.split_once(':')?;
    let rule_id_length = rule_id_length.parse::<usize>().ok()?;
    (!run_id.is_empty()
        && !control_id.is_empty()
        && !rule_id.is_empty()
        && rule_id.len() == rule_id_length)
        .then_some((run_id, framework_id, control_id, rule_id))
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
    /// A PDF artifact could not be rendered into memory.
    Export(std::io::Error),
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
    /// Linked evidence metadata has an expected digest, but the backing store
    /// has no record for its stable id.
    MissingEvidence {
        /// Stable evidence id that is absent from the backing store.
        evidence_id: String,
        /// Digest persisted by `SQLite`.
        expected: String,
    },
    /// The requested run does not exist in the local database.
    MissingRun(String),
    /// A URI-shaped database target was supplied where a local path is required.
    NonLocalTarget(String),
    /// The requested export format is not one of the existing artifact paths.
    UnsupportedExportFormat(String),
    /// A named packaged migration failed and its transaction was rolled back.
    Migration {
        /// Packaged migration name, for example `0001-initial`.
        name: String,
        /// Underlying `SQLite` error that failed the migration.
        source: rusqlite::Error,
    },
    /// A named packaged migration was rejected before execution because it
    /// contains a destructive operation against persisted corpus data.
    DestructiveMigration {
        /// Packaged migration name, for example `0002-drop-evidence-metadata`.
        name: String,
        /// Destructive operation detected in the migration SQL.
        operation: String,
    },
}

impl LocalDatabaseError {
    /// Whether this error reports a linked-evidence integrity failure.
    #[must_use]
    pub fn is_integrity_error(&self) -> bool {
        matches!(
            self,
            LocalDatabaseError::IntegrityMismatch { .. }
                | LocalDatabaseError::MissingEvidence { .. }
        )
    }

    /// Returns the expected digest for a linked-evidence integrity failure.
    #[must_use]
    pub fn expected_digest(&self) -> Option<&str> {
        match self {
            LocalDatabaseError::IntegrityMismatch { expected, .. }
            | LocalDatabaseError::MissingEvidence { expected, .. } => Some(expected),
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
            LocalDatabaseError::Export(error) => {
                write!(formatter, "local database export error: {error}")
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
            LocalDatabaseError::MissingEvidence {
                evidence_id,
                expected,
            } => write!(
                formatter,
                "linked evidence {evidence_id} is missing: expected {expected}"
            ),
            LocalDatabaseError::MissingRun(run_id) => {
                write!(formatter, "local database run {run_id} is missing")
            }
            LocalDatabaseError::NonLocalTarget(target) => {
                write!(formatter, "local database target {target} is non-local")
            }
            LocalDatabaseError::UnsupportedExportFormat(format) => {
                write!(formatter, "unsupported local database export format: {format}")
            }
            LocalDatabaseError::Migration { name, source } => {
                write!(
                    formatter,
                    "local database migration {name} failed: {source}"
                )
            }
            LocalDatabaseError::DestructiveMigration { name, operation } => {
                write!(
                    formatter,
                    "local database migration {name} rejected as destructive: {operation}"
                )
            }
        }
    }
}

impl Error for LocalDatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LocalDatabaseError::Io(error) | LocalDatabaseError::Export(error) => Some(error),
            LocalDatabaseError::Sqlite(error) => Some(error),
            LocalDatabaseError::Schema(_)
            | LocalDatabaseError::IntegrityMismatch { .. }
            | LocalDatabaseError::MissingEvidence { .. }
            | LocalDatabaseError::MissingRun(_)
            | LocalDatabaseError::NonLocalTarget(_)
            | LocalDatabaseError::UnsupportedExportFormat(_)
            | LocalDatabaseError::DestructiveMigration { .. } => None,
            LocalDatabaseError::Migration { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::Classification;

    #[test]
    fn hardcoded_persisted_corpus_tables_match_current_schema() {
        let connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(INITIAL_SCHEMA_SQL)
            .expect("create the current schema");
        let schema_tables = connection
            .prepare(
                "SELECT name
                 FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .expect("prepare schema table query")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query current schema tables")
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("collect current schema tables");
        let protected_tables = PERSISTED_CORPUS_TABLES
            .iter()
            .map(|table_name| (*table_name).to_owned())
            .collect::<BTreeSet<_>>();

        assert_eq!(protected_tables, schema_tables);
    }

    #[test]
    fn legacy_rewrite_preserves_an_integrity_backed_classification() {
        let mut connection = Connection::open_in_memory().expect("open in-memory SQLite");
        apply_packaged_migrations(&mut connection, PACKAGED_MIGRATIONS)
            .expect("apply packaged migrations");
        let mut database = LocalDatabase { connection };
        database
            .write_completed_corpus(
                &Corpus::new("2026-06-24T13:16:28Z")
                    .with_run_id("classified-run")
                    .with_classified_evidence(
                        "classified-evidence",
                        "config",
                        ".env.example:3",
                        Classification::Secret,
                        "sha256:classified",
                    ),
            )
            .expect("write classified evidence");
        database
            .write_completed_corpus(
                &Corpus::new("2026-06-24T13:16:28Z")
                    .with_run_id("legacy-run")
                    .with_evidence("classified-evidence", ".env.example:3"),
            )
            .expect("rewrite through the legacy metadata path");

        let classification: String = database
            .connection
            .query_row(
                "SELECT classification FROM evidence_metadata WHERE id = ?1",
                ["classified-evidence"],
                |row| row.get(0),
            )
            .expect("read the preserved classification");
        assert_eq!(classification, "Secret");
        let snapshot: (String, String) = database
            .connection
            .query_row(
                "SELECT digest, classification
                 FROM run_evidence_links
                 WHERE run_id = 'legacy-run' AND evidence_id = 'classified-evidence'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read the legacy run evidence snapshot");
        assert_eq!(
            snapshot,
            ("sha256:classified".to_owned(), "Secret".to_owned())
        );
    }

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
    fn result_filter_migration_backfills_a_parseable_result_identity() {
        let mut connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(
                "CREATE TABLE control_results (id TEXT PRIMARY KEY);
                 CREATE TABLE compliance_gaps (
                   id TEXT PRIMARY KEY,
                   run_id TEXT NOT NULL,
                   status TEXT NOT NULL,
                   severity TEXT NOT NULL,
                   control_id TEXT NOT NULL,
                   rule_id TEXT NOT NULL
                 );",
            )
            .expect("create the legacy result schema");
        let row_id = control_result_row_id(
            "legacy-run",
            "gdpr-eprivacy",
            "legacy-control",
            "legacy-rule",
        );
        connection
            .execute("INSERT INTO control_results(id) VALUES (?1)", [&row_id])
            .expect("insert the legacy result row");
        connection
            .execute(
                "INSERT INTO compliance_gaps(
                   id, run_id, status, severity, control_id, rule_id
                 ) VALUES ('legacy-gap', ?1, 'FAIL', 'major', ?2, ?3)",
                ["legacy-run", "legacy-control", "legacy-rule"],
            )
            .expect("insert the matching legacy gap");

        let transaction = connection
            .transaction()
            .expect("start migration transaction");
        apply_result_query_filters_migration(&transaction)
            .expect("apply the result-filter migration");
        transaction.commit().expect("commit the migration");

        let migrated: (String, String, String, String) = connection
            .query_row(
                "SELECT run_id, control_id, rule_id, status
                 FROM control_results
                 WHERE id = ?1",
                [&row_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read the migrated result row");
        assert_eq!(
            migrated,
            (
                "legacy-run".to_owned(),
                "legacy-control".to_owned(),
                "legacy-rule".to_owned(),
                "FAIL".to_owned(),
            )
        );
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
    fn export_reconstruction_migration_backfills_a_recognized_v7_database() {
        let mut connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(INITIAL_SCHEMA_SQL)
            .expect("create the current table shapes");
        connection
            .execute_batch(
                "DROP TABLE run_framework_links;
                 DROP TABLE run_control_links;
                 ALTER TABLE scan_runs DROP COLUMN executed_at;
                 ALTER TABLE control_results DROP COLUMN framework_id;
                 ALTER TABLE control_results DROP COLUMN severity;
                 ALTER TABLE control_results DROP COLUMN weight;
                 ALTER TABLE control_results DROP COLUMN reason;
                 ALTER TABLE control_results DROP COLUMN executed_at;
                 ALTER TABLE control_results DROP COLUMN execution_metadata;
                 CREATE TABLE schema_migrations (
                   version INTEGER PRIMARY KEY,
                   name TEXT NOT NULL,
                   applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO schema_migrations(version, name) VALUES
                   (1, '0001-initial'),
                   (2, '0002-run-evidence-links'),
                   (3, '0003-gap-query-filters'),
                   (4, '0004-evidence-locators'),
                   (5, '0005-result-query-filters'),
                   (6, '0006-run-evidence-index'),
                   (7, '0007-evidence-classifications');
                 INSERT INTO scan_runs(id) VALUES ('legacy-run');
                 INSERT INTO frameworks(id, version) VALUES ('gdpr-eprivacy', '2016-679');
                 INSERT INTO controls(id) VALUES ('control');
                 INSERT INTO control_results(
                   id, run_id, control_id, rule_id, status, evidence_id
                 ) VALUES (
                   '10:legacy-run:13:gdpr-eprivacy:7:control:rule',
                   'legacy-run', 'control', 'rule', 'FAIL', ''
                 );
                 INSERT INTO compliance_gaps(
                   id, run_id, status, severity, control_id, rule_id
                 ) VALUES (
                   'legacy-gap', 'legacy-run', 'FAIL', 'major', 'control', 'rule'
                 );
                 PRAGMA user_version = 7;",
            )
            .expect("record a recognized v7 schema");

        apply_packaged_migrations(&mut connection, PACKAGED_MIGRATIONS)
            .expect("apply the export reconstruction migration");

        assert_eq!(connection_schema_version(&connection).unwrap(), 8);
        let result_metadata: (String, String) = connection
            .query_row(
                "SELECT framework_id, severity FROM control_results WHERE run_id = 'legacy-run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read backfilled result metadata");
        assert_eq!(
            result_metadata,
            ("gdpr-eprivacy".to_owned(), "major".to_owned())
        );
        let catalog_links: (i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM run_framework_links WHERE run_id = 'legacy-run'),
                   (SELECT COUNT(*) FROM run_control_links WHERE run_id = 'legacy-run')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read backfilled catalog links");
        assert_eq!(catalog_links, (1, 1));
    }

    #[test]
    fn export_reconstruction_rejects_a_missing_execution_timestamp() {
        let persisted = PersistedExportResult {
            framework_id: "framework".to_owned(),
            control_id: "control".to_owned(),
            rule_id: "rule".to_owned(),
            status: "PASS".to_owned(),
            evidence_id: String::new(),
            severity: "major".to_owned(),
            weight: 1,
            reason: None,
            executed_at: String::new(),
            execution_metadata: String::new(),
        };

        let error = reconstruct_control_result(&persisted, "")
            .expect_err("missing result and run timestamps are rejected");

        assert!(error.to_string().contains("execution timestamp is missing"));
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

    #[test]
    fn current_packaged_schema_version_uses_final_ascending_migration_version() {
        let migrations = [
            PackagedMigration::new(1, "0001-initial", ""),
            PackagedMigration::new(2, "0002-middle", ""),
            PackagedMigration::new(3, "0003-future", ""),
        ];

        assert_eq!(
            current_packaged_schema_version(&migrations)
                .expect("current packaged schema version can be resolved"),
            3
        );
    }

    #[test]
    fn current_packaged_schema_version_rejects_empty_migration_stack() {
        let error =
            current_packaged_schema_version(&[]).expect_err("empty migrations are rejected");

        assert!(
            error
                .to_string()
                .contains(EMPTY_PACKAGED_MIGRATIONS_MESSAGE),
            "empty migration stacks should be reported explicitly, got {error}"
        );
    }

    #[test]
    fn current_packaged_schema_version_rejects_duplicate_migration_versions() {
        let migrations = [
            PackagedMigration::new(1, "0001-initial", ""),
            PackagedMigration::new(1, "0001-duplicate", ""),
        ];

        let error = current_packaged_schema_version(&migrations)
            .expect_err("duplicate migration versions are rejected");

        assert!(
            error
                .to_string()
                .contains("duplicate packaged migration version 1"),
            "duplicate migration versions should be reported explicitly, got {error}"
        );
    }

    #[test]
    fn current_packaged_schema_version_rejects_out_of_order_migration_versions() {
        let migrations = [
            PackagedMigration::new(1, "0001-initial", ""),
            PackagedMigration::new(3, "0003-future", ""),
            PackagedMigration::new(2, "0002-middle", ""),
        ];

        let error = current_packaged_schema_version(&migrations)
            .expect_err("out-of-order migration versions are rejected");

        assert!(
            error
                .to_string()
                .contains("migrations must be ordered by ascending version"),
            "out-of-order migration versions should be reported explicitly, got {error}"
        );
    }
}
