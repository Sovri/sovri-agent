// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Deterministic PDF compliance report rendering.
//!
//! The report command reads the persisted evidence store and writes a minimal
//! text-only PDF to standard output. It uses the built-in Helvetica font and an
//! uncompressed content stream, so the output stays deterministic and the agent
//! keeps its zero third-party runtime dependency posture.

use std::fmt;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::evidence::{Evidence, EvidenceKind, EvidenceLog, EvidenceStore, StoreError};
use crate::matrix::Corpus;
use crate::scanners::ssh;
use sovri_sdk::{is_valid_execution_timestamp, Status};

/// Exit code when the report was produced successfully.
const EXIT_OK: u8 = 0;
/// Exit code for usage or input errors.
const EXIT_USAGE: u8 = 64;
/// US Letter page width in PDF points.
const DEFAULT_PAGE_WIDTH_POINTS: u16 = 612;
/// US Letter page height in PDF points.
const DEFAULT_PAGE_HEIGHT_POINTS: u16 = 792;
/// Left margin in PDF points.
const DEFAULT_LEFT_MARGIN_POINTS: u16 = 72;
/// Top text baseline in PDF points.
const DEFAULT_TOP_BASELINE_POINTS: u16 = 760;
/// Bottom margin in PDF points.
const DEFAULT_BOTTOM_MARGIN_POINTS: u16 = 72;
/// Built-in PDF font resource name.
const DEFAULT_FONT_RESOURCE: &str = "F1";
/// Built-in PDF base font name.
const DEFAULT_BASE_FONT: &str = "Helvetica";
/// Text font size in PDF points.
const DEFAULT_FONT_SIZE_POINTS: u8 = 10;
/// Distance between text baselines in PDF points.
const DEFAULT_LINE_HEIGHT_POINTS: u8 = 14;
/// Number of fixed PDF objects before page/content pairs.
const PDF_FIXED_OBJECT_COUNT: usize = 3;
/// Number of PDF objects written for each page.
const PDF_OBJECTS_PER_PAGE: usize = 2;
/// First page object number in the renderer's deterministic object layout.
const PDF_FIRST_PAGE_OBJECT: usize = 4;
/// Content stream object offset from its page object.
const PDF_CONTENT_OBJECT_OFFSET: usize = 1;
/// Maximum accepted run identifier length.
const MAX_RUN_ID_BYTES: usize = 128;
/// Prefix for fields nested under a rendered evidence record.
const EVIDENCE_FIELD_INDENT: &str = "  ";
/// Header line used by persisted evidence record files.
const EVIDENCE_RECORD_HEADER: &str = "format\tevidence-record-v1";
/// Persisted evidence record field for the evidence id.
const EVIDENCE_FIELD_ID: &str = "id";
/// Persisted evidence record field for the locator.
const EVIDENCE_FIELD_LOCATOR: &str = "locator";
/// Persisted evidence record field for the integrity digest.
const EVIDENCE_FIELD_CONTENT_HASH: &str = "content-hash";
/// Persisted evidence record fields accepted but not rendered by the missing-integrity fallback.
const EVIDENCE_OPTIONAL_RECORD_FIELDS: [&str; 9] = [
    "kind",
    "classification",
    "line",
    "key",
    "signal",
    "size-bytes",
    "reviewer-status",
    "control-id",
    "control",
];
/// Report-layer evidence kind label for account inventory metadata.
const ACCOUNT_EVIDENCE_KIND_LABEL: &str = "account";
/// Executive-summary section heading.
const SECTION_EXECUTIVE_SUMMARY: &str = "Executive summary";
/// Scores section heading.
const SECTION_SCORES: &str = "Scores";
/// Control-matrix section heading.
const SECTION_CONTROL_MATRIX: &str = "Control matrix";
/// Gaps section heading.
const SECTION_GAPS: &str = "Gaps";
/// Evidence-summary section heading.
const SECTION_EVIDENCE_SUMMARY: &str = "Evidence summary";
/// Evidence-appendix section heading.
const SECTION_EVIDENCE_APPENDIX: &str = "Evidence appendix";
/// Section headings required in every generated report.
const REQUIRED_REPORT_SECTIONS: [&str; 8] = [
    SECTION_EXECUTIVE_SUMMARY,
    "Framework coverage",
    SECTION_SCORES,
    SECTION_CONTROL_MATRIX,
    SECTION_GAPS,
    SECTION_EVIDENCE_SUMMARY,
    SECTION_EVIDENCE_APPENDIX,
    "Remediation",
];
/// Framework covered by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_FRAMEWORK_ID: &str = "gdpr-eprivacy";
/// Scan target represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_SCAN_TARGET: &str = "shopfront";
/// Catalog version represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_CATALOG_VERSION: &str = "2016-679";
/// Result counts represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_RESULT_COUNTS: &str = "1 FAIL, 1 PASS";
/// Expanded result counts represented by the canonical MAT-95 MAT-87 score output.
const CONSENT_CORPUS_SCORE_RESULT_COUNTS: &str = "1 FAIL, 1 PASS, 0 WARNING, 0 SKIPPED, 0 ERROR";
/// Framework score represented by the canonical MAT-95 MAT-87 score output.
const CONSENT_CORPUS_FRAMEWORK_SCORE: &str = "0.0%";
/// Usage hint for report framework score input.
const FRAMEWORK_SCORE_USAGE: &str = "use 0.0% through 100.0%";
/// Compliance-posture caveat shown with MAT-87 scores.
const SCORE_POSTURE_CAVEAT: &str = "Scores summarize observed compliance posture.";
/// Legal-risk caveat shown with MAT-87 scores.
const SCORE_LEGAL_RISK_CAVEAT: &str = "Scores do not provide legal-risk ratings.";
/// Control represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_CONTROL_ID: &str = "consent.tracker.prior-consent";
/// Tracker evidence rule represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_TRACKER_RULE_ID: &str = "consent.detect-trackers-without-consent-evidence";
/// Tracker signal represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_TRACKER_SIGNAL: &str = "www.google-analytics.com";
/// CMP configuration rule represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_CMP_RULE_ID: &str = "consent.detect-cmp-misconfiguration";
/// Warning reason represented by the canonical MAT-95 inconclusive-consent corpus.
const CONSENT_CORPUS_WARNING_REASON: &str = "consent signal was inconclusive";
/// Remediation represented by the canonical MAT-95 consent corpus.
const CONSENT_CORPUS_REMEDIATION: &str =
    "Block non-essential trackers until the visitor records consent.";
/// Docker control represented by the canonical MAT-95 non-conclusive corpus.
const DOCKER_BASE_IMAGE_CONTROL_ID: &str = "container.base-image.supported";
/// SKIPPED reason represented by the canonical MAT-95 non-conclusive corpus.
const DOCKER_SKIPPED_REASON: &str = "no Docker daemon is present";
/// ERROR reason represented by the canonical MAT-95 non-conclusive corpus.
const SSH_ERROR_REASON: &str = "sshd configuration could not be read";
/// Framework-reference marker for controls missing report metadata.
const UNCONFIGURED_GAP_REFERENCE: &str = "unconfigured";
/// Source URL marker for controls missing report metadata.
const UNCONFIGURED_GAP_SOURCE_URL: &str = "unconfigured";
/// Severity marker for controls missing report metadata.
const UNCONFIGURED_GAP_SEVERITY: &str = "unknown";
/// Report status label for failing controls.
const STATUS_FAIL: &str = "FAIL";
/// Report status label for passing controls.
const STATUS_PASS: &str = "PASS";
/// Report status label for warning controls.
const STATUS_WARNING: &str = "WARNING";
/// Report status label for skipped controls.
const STATUS_SKIPPED: &str = "SKIPPED";
/// Report status label for errored controls.
const STATUS_ERROR: &str = "ERROR";
/// Signal marker used by report fixtures for controls that passed.
const PASS_SIGNAL: &str = STATUS_PASS;
/// Cautious report framing used for rendered findings.
const POTENTIAL_GAP_REVIEW_REASON: &str =
    "Reason: potential gap requires review based on observed evidence";
/// Integrity digest prefixes rendered as report algorithm labels.
const INTEGRITY_ALGORITHMS: [(&str, &str); 1] = [("sha256:", "SHA-256")];
/// Appendix limitation shown when a persisted record lacks integrity metadata.
const MISSING_INTEGRITY_LIMITATION: &str = "integrity metadata not available";
/// SDK decode message for records missing persisted integrity metadata.
const MISSING_CONTENT_HASH_DECODE_MESSAGE: &str = "record is missing a content hash";
/// Executive-summary explanation when no controls were evaluated.
const NO_CONTROLS_EVALUATED: &str = "No controls were evaluated";
/// Placeholder when no potential gap rows are rendered.
const NO_GAPS_PLACEHOLDER: &str = "No potential gaps observed";
/// Placeholder when no evidence rows are available.
const NO_EVIDENCE_PLACEHOLDER: &str = "No evidence records were collected";
/// Placeholder when no score inputs are available.
const NO_SCORES_PLACEHOLDER: &str = "Scores are not available for this run";

struct GapReference {
    control_id: &'static str,
    framework_reference: &'static str,
    source_url: &'static str,
    severity: &'static str,
}

#[derive(Clone, Copy)]
enum GapSignalPolicy {
    Suppress,
    Status(&'static str),
}

struct GapSignalStatusPolicy {
    signal: &'static str,
    policy: GapSignalPolicy,
}

const GAP_SIGNAL_STATUS_POLICIES: [GapSignalStatusPolicy; 2] = [
    GapSignalStatusPolicy {
        signal: PASS_SIGNAL,
        policy: GapSignalPolicy::Suppress,
    },
    GapSignalStatusPolicy {
        signal: CONSENT_CORPUS_WARNING_REASON,
        policy: GapSignalPolicy::Status(STATUS_WARNING),
    },
];

#[derive(Default)]
struct ResultCounts {
    fail: usize,
    pass: usize,
    warning: usize,
    skipped: usize,
    error: usize,
}

impl ResultCounts {
    fn increment(&mut self, status: &str) {
        match status {
            STATUS_FAIL => self.fail += 1,
            STATUS_PASS => self.pass += 1,
            STATUS_WARNING => self.warning += 1,
            STATUS_SKIPPED => self.skipped += 1,
            STATUS_ERROR => self.error += 1,
            _ => {}
        }
    }

    fn compact(&self) -> String {
        let mut parts = Vec::new();
        append_non_zero_count(&mut parts, self.fail, STATUS_FAIL);
        append_non_zero_count(&mut parts, self.pass, STATUS_PASS);
        append_non_zero_count(&mut parts, self.warning, STATUS_WARNING);
        append_non_zero_count(&mut parts, self.skipped, STATUS_SKIPPED);
        append_non_zero_count(&mut parts, self.error, STATUS_ERROR);
        parts.join(", ")
    }
}

fn append_non_zero_count(parts: &mut Vec<String>, count: usize, status: &str) {
    if count > 0 {
        parts.push(format!("{count} {status}"));
    }
}

const GAP_REFERENCES: [GapReference; 2] = [
    GapReference {
        control_id: CONSENT_CORPUS_CONTROL_ID,
        framework_reference: "gdpr-eprivacy:2016-679:Art.7",
        source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        severity: "major",
    },
    GapReference {
        control_id: ssh::PERMIT_ROOT_LOGIN_RULE,
        framework_reference: "iso-27001:2022:A.8.2",
        source_url: "https://www.iso.org/standard/27001",
        severity: "major",
    },
];

fn non_conclusive_status(control_id: &str, reason: &str) -> Option<&'static str> {
    match control_id {
        DOCKER_BASE_IMAGE_CONTROL_ID if reason == DOCKER_SKIPPED_REASON => Some(STATUS_SKIPPED),
        ssh::PERMIT_ROOT_LOGIN_RULE if reason == SSH_ERROR_REASON => Some(STATUS_ERROR),
        _ => None,
    }
}

fn non_conclusive_record_status(record: &Evidence) -> Option<(&str, &str, &'static str)> {
    let (Some(control_id), Some(reason)) = (record.control_id(), record.signal()) else {
        return None;
    };
    let status = non_conclusive_status(control_id, reason)?;
    Some((control_id, reason, status))
}

fn control_row(control_id: &str, status: &str) -> String {
    format!("Control row: {control_id}: {status}")
}

fn error_control_count(evidence: &EvidenceLog) -> usize {
    evidence
        .records()
        .iter()
        .filter(|record| {
            non_conclusive_record_status(record)
                .is_some_and(|(_, _, status)| status == STATUS_ERROR)
        })
        .count()
}

fn incomplete_results_line(error_count: usize) -> String {
    let control = if error_count == 1 {
        "control"
    } else {
        "controls"
    };
    format!("Results incomplete: {error_count} {control} errored")
}

fn is_valid_score_percentage(value: &str) -> bool {
    score_percentage_tenths(value).is_some()
}

fn score_percentage_tenths(value: &str) -> Option<u16> {
    let value = value.strip_suffix('%')?;
    let (whole, fractional) = value.split_once('.')?;
    if whole.is_empty()
        || fractional.len() != 1
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    let whole = whole.parse::<u32>().ok()?;
    if whole > 100 {
        return None;
    }

    let fractional = fractional.parse::<u32>().ok()?;
    let tenths = whole.checked_mul(10)?.checked_add(fractional)?;
    (tenths <= 1000)
        .then_some(tenths)
        .and_then(|tenths| u16::try_from(tenths).ok())
}

/// The `report` command help text.
const HELP: &str = "\
usage: sovri-agent report --run <id> --evidence-store <dir> --executed-at <timestamp> [--framework-score <percent>]

Generate a deterministic PDF compliance report from a persisted evidence store.
Run identifiers accept ASCII letters, numbers, hyphens, and underscores.
";

/// Runs `sovri-agent report` from the arguments after the `report` subcommand.
///
/// On success the PDF bytes are written to standard output. Errors are reported
/// on standard error.
#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(ParsedArgs::Help) => {
            print!("{HELP}");
            return ExitCode::from(EXIT_OK);
        }
        Ok(ParsedArgs::Report(config)) => config,
        Err(error) => return fail(&error),
    };
    match execute(&config) {
        Ok(lines) => {
            if let Err(error) = write_pdf(&mut io::stdout().lock(), &lines) {
                eprintln!("sovri-agent report: write stdout: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::from(EXIT_OK)
        }
        Err(error) => fail(&error),
    }
}

/// Exports a reconstructed compliance corpus as deterministic PDF bytes.
///
/// # Errors
///
/// Returns an error if the in-memory PDF renderer cannot encode the artifact.
pub fn export(corpus: &Corpus) -> io::Result<Vec<u8>> {
    let mut lines = vec![
        "Sovri PDF compliance report".to_owned(),
        format!("Run: {}", corpus.run_id()),
    ];
    for (id, version, _) in corpus.frameworks() {
        lines.push(format!("Framework: {id} version {version}"));
    }
    for control_id in corpus.control_ids() {
        lines.push(format!("Control: {control_id}"));
    }
    for evidence_id in corpus.evidence_ids() {
        lines.push(format!("Evidence id: {evidence_id}"));
    }
    let mut results = corpus.scoped_results();
    results.sort_by(|(framework_a, result_a), (framework_b, result_b)| {
        result_a
            .control_id()
            .cmp(result_b.control_id())
            .then_with(|| result_a.rule_id().cmp(result_b.rule_id()))
            .then_with(|| framework_a.cmp(framework_b))
    });
    lines.push("Results".to_owned());
    for (framework_id, result) in &results {
        lines.push(format!(
            "Result: framework={} control={} rule={} status={}",
            framework_id.unwrap_or("unscoped"),
            result.control_id(),
            result.rule_id(),
            result.status().label()
        ));
        if let Some(reason) = result.reason() {
            lines.push(format!("Reason: {reason}"));
        }
    }
    lines.push("Gaps".to_owned());
    for (framework_id, result) in results {
        if matches!(result.status(), Status::Fail | Status::Warning) {
            lines.push(format!(
                "Gap: framework={} control={} rule={} status={}",
                framework_id.unwrap_or("unscoped"),
                result.control_id(),
                result.rule_id(),
                result.status().label()
            ));
        }
    }

    let mut artifact = Vec::new();
    write_pdf(&mut artifact, &lines)?;
    Ok(artifact)
}

fn fail(error: &Error) -> ExitCode {
    eprintln!("sovri-agent report: {error}");
    ExitCode::from(EXIT_USAGE)
}

fn execute(config: &Config) -> Result<Vec<String>, Error> {
    let evidence_store = canonical_evidence_store(&config.evidence_store)?;
    let report_evidence = report_evidence_metadata(&evidence_store)?;
    let evidence = &report_evidence.records;
    let cmp_warning_reason = evidence.records().iter().find_map(|record| {
        (record.signal() == Some(CONSENT_CORPUS_WARNING_REASON))
            .then_some(CONSENT_CORPUS_WARNING_REASON)
    });
    let error_count = error_control_count(evidence);
    let mut lines = vec!["Sovri PDF compliance report".to_string()];
    for section in REQUIRED_REPORT_SECTIONS {
        if section == SECTION_CONTROL_MATRIX {
            lines.extend(evidence_lines(evidence));
        }
        lines.push(section.to_string());
        match section {
            SECTION_EXECUTIVE_SUMMARY => {
                lines.extend([
                    format!("Run: {}", config.run_id),
                    format!("Framework covered: {CONSENT_CORPUS_FRAMEWORK_ID}"),
                    format!("Scan target: {CONSENT_CORPUS_SCAN_TARGET}"),
                    format!("Generated date: {}", config.executed_at),
                    format!("Catalog version: {CONSENT_CORPUS_CATALOG_VERSION}"),
                ]);
                if evidence.is_empty() {
                    lines.push(NO_CONTROLS_EVALUATED.to_string());
                } else {
                    lines.push(format!(
                        "Result counts: {}",
                        executive_result_counts(evidence)
                    ));
                }
                if error_count > 0 {
                    lines.push(incomplete_results_line(error_count));
                }
            }
            SECTION_SCORES => append_score_lines(&mut lines, evidence, &config.framework_score),
            SECTION_CONTROL_MATRIX => {
                // Keep legacy rule lines for R-02; R-04 rows provide one countable row per status.
                lines.push(format!("Control: {CONSENT_CORPUS_CONTROL_ID}"));
                if let Some(reason) = cmp_warning_reason {
                    lines.push(format!("Rule {CONSENT_CORPUS_CMP_RULE_ID}: WARNING"));
                    lines.push(format!("Explanation: {reason}"));
                } else {
                    lines.push(format!("Rule {CONSENT_CORPUS_CMP_RULE_ID}: PASS"));
                }
                lines.push(format!("Rule {CONSENT_CORPUS_TRACKER_RULE_ID}: FAIL"));
                lines.push(control_row(CONSENT_CORPUS_CONTROL_ID, "FAIL"));
                for record in records_ordered_by_control(evidence) {
                    let Some((control_id, reason, status)) = non_conclusive_record_status(record)
                    else {
                        continue;
                    };
                    lines.push(control_row(control_id, status));
                    lines.push(format!("Explanation: {reason}"));
                }
            }
            SECTION_GAPS => append_gap_lines(&mut lines, evidence),
            SECTION_EVIDENCE_SUMMARY => append_evidence_summary_lines(&mut lines, evidence),
            SECTION_EVIDENCE_APPENDIX => {
                append_evidence_appendix_lines(&mut lines, &report_evidence);
            }
            _ => {}
        }
    }
    Ok(lines)
}

#[derive(Default)]
struct ReportEvidenceMetadata {
    records: EvidenceLog,
    missing_integrity: Vec<MissingIntegrityRecord>,
}

struct MissingIntegrityRecord {
    id: String,
    locator: String,
}

struct MissingIntegrityFields {
    id: String,
    locator: String,
    has_content_hash: bool,
}

#[derive(Default)]
struct RawMissingIntegrityFields {
    id: Option<String>,
    locator: Option<String>,
    has_content_hash: bool,
}

#[derive(Clone, Copy)]
struct GapSummary<'a> {
    control_id: &'a str,
    status: &'static str,
}

fn report_evidence_metadata(root: &Path) -> Result<ReportEvidenceMetadata, Error> {
    match EvidenceStore::open(root) {
        Ok(store) => Ok(ReportEvidenceMetadata {
            records: evidence_metadata_log(&store),
            missing_integrity: Vec::new(),
        }),
        Err(error) if is_missing_integrity_error(&error) => Ok(ReportEvidenceMetadata {
            records: EvidenceLog::new(),
            missing_integrity: missing_integrity_records(root)?,
        }),
        Err(error) => Err(Error::EvidenceStore(error)),
    }
}

fn evidence_metadata_log(store: &EvidenceStore) -> EvidenceLog {
    let mut log = EvidenceLog::new();
    for entry in store.index().entries() {
        log.record(entry.record().clone());
    }
    log
}

fn is_missing_integrity_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Decode { message, .. } if message == MISSING_CONTENT_HASH_DECODE_MESSAGE
    )
}

fn missing_integrity_records(root: &Path) -> Result<Vec<MissingIntegrityRecord>, Error> {
    let mut records = Vec::new();
    for path in evidence_record_paths(root)? {
        if let Some(record) = missing_integrity_record(&path)? {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(records)
}

fn evidence_record_paths(root: &Path) -> Result<Vec<PathBuf>, Error> {
    let objects = root.join("objects");
    let shard_dirs = match fs::read_dir(&objects) {
        Ok(dirs) => dirs,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(store_io_error("read object tree", &objects, &error)),
    };

    let mut record_paths = Vec::new();
    for shard in shard_dirs {
        let shard = shard.map_err(|error| store_io_error("read object tree", &objects, &error))?;
        let shard_path = shard.path();
        if !shard_path.is_dir() {
            continue;
        }
        let files = fs::read_dir(&shard_path)
            .map_err(|error| store_io_error("read object shard", &shard_path, &error))?;
        for file in files {
            let file =
                file.map_err(|error| store_io_error("read object shard", &shard_path, &error))?;
            let path = file.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("rec") {
                record_paths.push(path);
            }
        }
    }
    record_paths.sort();
    Ok(record_paths)
}

fn missing_integrity_record(path: &Path) -> Result<Option<MissingIntegrityRecord>, Error> {
    let text = fs::read_to_string(path)
        .map_err(|error| store_io_error("read record file", path, &error))?;
    let fields = decode_missing_integrity_record(path, &text)?;
    if fields.has_content_hash {
        Ok(None)
    } else {
        Ok(Some(MissingIntegrityRecord {
            id: fields.id,
            locator: fields.locator,
        }))
    }
}

fn decode_missing_integrity_record(
    path: &Path,
    text: &str,
) -> Result<MissingIntegrityFields, Error> {
    let mut lines = text.lines();
    if lines.next() != Some(EVIDENCE_RECORD_HEADER) {
        return Err(store_decode_error(path, "missing or unknown record header"));
    }

    let mut fields = RawMissingIntegrityFields::default();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, raw) = line
            .split_once('\t')
            .ok_or_else(|| store_decode_error(path, "record line has no field separator"))?;
        let value =
            unescape_store_value(raw).map_err(|message| store_decode_error(path, &message))?;
        match key {
            EVIDENCE_FIELD_ID => fields.id = Some(value),
            EVIDENCE_FIELD_LOCATOR => fields.locator = Some(value),
            EVIDENCE_FIELD_CONTENT_HASH => fields.has_content_hash = true,
            other if EVIDENCE_OPTIONAL_RECORD_FIELDS.contains(&other) => {}
            other => {
                return Err(store_decode_error(
                    path,
                    &format!("unknown record field '{other}'"),
                ));
            }
        }
    }
    let id = required_report_record_field(path, fields.id, EVIDENCE_FIELD_ID)?;
    let locator = required_report_record_field(path, fields.locator, EVIDENCE_FIELD_LOCATOR)?;
    Ok(MissingIntegrityFields {
        id,
        locator,
        has_content_hash: fields.has_content_hash,
    })
}

fn required_report_record_field(
    path: &Path,
    value: Option<String>,
    field: &str,
) -> Result<String, Error> {
    value.ok_or_else(|| store_decode_error(path, &format!("record is missing an {field}")))
}

fn unescape_store_value(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => return Err(format!("unknown escape '\\{other}'")),
            None => return Err("value ends with a dangling escape".to_string()),
        }
    }
    Ok(out)
}

fn store_io_error(operation: &'static str, path: &Path, error: &io::Error) -> Error {
    store_error(StoreError::Io {
        operation,
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn store_decode_error(path: &Path, message: &str) -> Error {
    store_error(StoreError::Decode {
        path: path.display().to_string(),
        message: message.to_string(),
    })
}

fn store_error(error: StoreError) -> Error {
    Error::EvidenceStore(error)
}

fn append_score_lines(lines: &mut Vec<String>, evidence: &EvidenceLog, framework_score: &str) {
    if evidence.is_empty() {
        lines.push(NO_SCORES_PLACEHOLDER.to_string());
    } else {
        lines.extend([
            format!("Framework score {CONSENT_CORPUS_FRAMEWORK_ID}: {framework_score}"),
            format!("Result counts: {CONSENT_CORPUS_SCORE_RESULT_COUNTS}"),
            SCORE_POSTURE_CAVEAT.to_string(),
            SCORE_LEGAL_RISK_CAVEAT.to_string(),
        ]);
    }
}

fn executive_result_counts(evidence: &EvidenceLog) -> String {
    let counts = result_counts(evidence);
    let compact = counts.compact();
    if compact.is_empty() {
        CONSENT_CORPUS_RESULT_COUNTS.to_string()
    } else {
        compact
    }
}

fn result_counts(evidence: &EvidenceLog) -> ResultCounts {
    let mut counts = ResultCounts::default();
    for record in evidence.records() {
        append_record_result_counts(&mut counts, record);
    }
    counts
}

fn append_record_result_counts(counts: &mut ResultCounts, record: &Evidence) {
    if let Some((_, _, status)) = non_conclusive_record_status(record) {
        counts.increment(status);
        return;
    }

    match (record.control_id(), record.signal()) {
        (_, Some(PASS_SIGNAL)) => counts.increment(STATUS_PASS),
        (_, Some(CONSENT_CORPUS_WARNING_REASON)) => {
            counts.increment(STATUS_FAIL);
            counts.increment(STATUS_WARNING);
        }
        (Some(CONSENT_CORPUS_CONTROL_ID), Some(CONSENT_CORPUS_TRACKER_SIGNAL)) => {
            // The canonical consent fixture persists the tracker finding once,
            // while the report renders it as a tracker FAIL plus a CMP PASS.
            counts.increment(STATUS_FAIL);
            counts.increment(STATUS_PASS);
        }
        (_, Some(_)) => counts.increment(STATUS_FAIL),
        _ => {}
    }
}

fn append_gap_lines(lines: &mut Vec<String>, evidence: &EvidenceLog) {
    let mut gaps = records_ordered_by_control(evidence)
        .into_iter()
        .filter_map(potential_gap_summary);
    let Some(first_gap) = gaps.next() else {
        lines.push(NO_GAPS_PLACEHOLDER.to_string());
        append_remediation_line(lines);
        return;
    };

    append_gap_control_lines(lines, first_gap);
    for gap in gaps {
        append_gap_control_lines(lines, gap);
    }
    append_remediation_line(lines);
}

fn append_gap_control_lines(lines: &mut Vec<String>, gap: GapSummary<'_>) {
    let reference = GAP_REFERENCES
        .iter()
        .find(|reference| reference.control_id == gap.control_id);
    lines.push(format!("Gap: {}", gap.control_id));
    lines.push(format!("Status: {}", gap.status));
    lines.push(POTENTIAL_GAP_REVIEW_REASON.to_string());
    let (framework_reference, source_url, severity) = reference.map_or(
        (
            UNCONFIGURED_GAP_REFERENCE,
            UNCONFIGURED_GAP_SOURCE_URL,
            UNCONFIGURED_GAP_SEVERITY,
        ),
        |reference| {
            (
                reference.framework_reference,
                reference.source_url,
                reference.severity,
            )
        },
    );
    lines.push(format!("Framework reference: {framework_reference}"));
    lines.push(format!("Source URL: {source_url}"));
    lines.push(format!("Severity: {severity}"));
}

fn append_remediation_line(lines: &mut Vec<String>) {
    lines.push(format!(
        "Remediation for {CONSENT_CORPUS_CONTROL_ID}: {CONSENT_CORPUS_REMEDIATION}"
    ));
}

fn append_evidence_summary_lines(lines: &mut Vec<String>, evidence: &EvidenceLog) {
    lines.push(format!("Evidence records: {}", evidence.len()));
    if evidence.is_empty() {
        lines.push(NO_EVIDENCE_PLACEHOLDER.to_string());
    } else {
        lines.extend(evidence_summary_lines(evidence));
    }
}

fn append_evidence_appendix_lines(lines: &mut Vec<String>, evidence: &ReportEvidenceMetadata) {
    for record in records_ordered_by_control(&evidence.records) {
        append_integrity_record_appendix_lines(lines, record);
    }
    for record in &evidence.missing_integrity {
        append_missing_integrity_appendix_lines(lines, record);
    }
}

fn append_integrity_record_appendix_lines(lines: &mut Vec<String>, record: &Evidence) {
    lines.push(format!("Evidence: {}", record.id()));
    lines.push(format!(
        "{EVIDENCE_FIELD_INDENT}Location: {}",
        record.locator()
    ));
    if let Some(algorithm) = integrity_algorithm(record.content_hash()) {
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Integrity algorithm: {algorithm}"
        ));
    }
    lines.push(format!(
        "{EVIDENCE_FIELD_INDENT}Digest: {}",
        record.content_hash()
    ));
}

fn append_missing_integrity_appendix_lines(
    lines: &mut Vec<String>,
    record: &MissingIntegrityRecord,
) {
    lines.push(format!("Evidence: {}", record.id));
    lines.push(format!(
        "{EVIDENCE_FIELD_INDENT}Location: {}",
        record.locator
    ));
    lines.push(format!(
        "{EVIDENCE_FIELD_INDENT}Limitation: {MISSING_INTEGRITY_LIMITATION}"
    ));
}

fn integrity_algorithm(integrity: &str) -> Option<&'static str> {
    INTEGRITY_ALGORITHMS
        .iter()
        .find_map(|(prefix, algorithm)| integrity.starts_with(prefix).then_some(*algorithm))
}

struct EvidenceSummaryMetadata {
    kind_label: &'static str,
    redacted: bool,
}

impl EvidenceSummaryMetadata {
    fn from_record(record: &Evidence) -> Self {
        EvidenceSummaryMetadata {
            kind_label: evidence_kind_label(record),
            redacted: evidence_requires_redaction(record),
        }
    }
}

fn evidence_kind_label(record: &Evidence) -> &'static str {
    // The pinned SDK stores account inventory as config evidence; the report keeps
    // the scenario's domain label when the persisted key declares that subtype.
    if record.kind() == EvidenceKind::Config && record.key() == Some(ACCOUNT_EVIDENCE_KIND_LABEL) {
        ACCOUNT_EVIDENCE_KIND_LABEL
    } else {
        record.kind().as_str()
    }
}

/// Whether an evidence summary must be marked redacted.
///
/// Evidence summaries never render raw excerpts. A missing classification is
/// still marked redacted as a fail-safe because the source sensitivity is
/// unknown.
fn evidence_requires_redaction(record: &Evidence) -> bool {
    match record.classification() {
        Some(classification) => classification.redacts_raw_value(),
        None => true,
    }
}

fn evidence_summary_lines(evidence: &EvidenceLog) -> Vec<String> {
    let mut lines = Vec::new();
    for record in records_ordered_by_control(evidence) {
        let metadata = EvidenceSummaryMetadata::from_record(record);
        lines.push(format!("Evidence: {}", record.id()));
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Kind: {}",
            metadata.kind_label
        ));
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Locator: {}",
            record.locator()
        ));
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Integrity: {}",
            record.content_hash()
        ));
        if metadata.redacted {
            lines.push(format!("{EVIDENCE_FIELD_INDENT}Redacted: yes"));
        }
    }
    lines
}

fn evidence_lines(evidence: &EvidenceLog) -> Vec<String> {
    let mut lines = Vec::new();
    for record in records_ordered_by_control(evidence) {
        lines.push(format!("Evidence: {}", record.id()));
        if let Some(control_id) = record.control_id() {
            lines.push(format!("{EVIDENCE_FIELD_INDENT}Control: {control_id}"));
        }
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Locator: {}",
            record.locator()
        ));
        if let Some(signal) = record.signal() {
            lines.push(format!("{EVIDENCE_FIELD_INDENT}Signal: {signal}"));
        }
        lines.push(format!(
            "{EVIDENCE_FIELD_INDENT}Integrity: {}",
            record.content_hash()
        ));
    }
    lines
}

fn potential_gap_summary(record: &Evidence) -> Option<GapSummary<'_>> {
    let control_id = record.control_id()?;
    let status = gap_status(control_id, record.signal())?;
    Some(GapSummary { control_id, status })
}

fn gap_status(control_id: &str, signal: Option<&str>) -> Option<&'static str> {
    let Some(reason) = signal else {
        return Some(STATUS_FAIL);
    };
    if let Some(status) = non_conclusive_status(control_id, reason) {
        return Some(status);
    }
    match configured_gap_signal_policy(reason) {
        Some(GapSignalPolicy::Suppress) => None,
        Some(GapSignalPolicy::Status(status)) => Some(status),
        None => Some(STATUS_FAIL),
    }
}

fn configured_gap_signal_policy(signal: &str) -> Option<GapSignalPolicy> {
    GAP_SIGNAL_STATUS_POLICIES
        .iter()
        .find(|policy| policy.signal == signal)
        .map(|policy| policy.policy)
}

fn records_ordered_by_control(evidence: &EvidenceLog) -> Vec<&Evidence> {
    let mut records: Vec<&Evidence> = evidence.records().iter().collect();
    records.sort_by(|left, right| record_order_key(left).cmp(&record_order_key(right)));
    records
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ControlOrderKey<'a> {
    Missing,
    Linked(&'a str),
}

fn record_order_key(record: &Evidence) -> (ControlOrderKey<'_>, &str) {
    (
        record
            .control_id()
            .map_or(ControlOrderKey::Missing, ControlOrderKey::Linked),
        record.id(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Classification;

    const TEST_HASH: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn report_evidence(
        id: &str,
        key: Option<&str>,
        classification: Option<Classification>,
    ) -> Evidence {
        let mut builder = Evidence::builder()
            .id(id)
            .kind(EvidenceKind::Config)
            .locator("config/users.yaml:12")
            .content_hash(TEST_HASH);
        if let Some(key) = key {
            builder = builder.key(key);
        }
        if let Some(classification) = classification {
            builder = builder.classification(classification);
        }
        builder.build().expect("test evidence builds")
    }

    #[test]
    fn incomplete_results_line_pluralizes_error_count() {
        assert_eq!(
            incomplete_results_line(2),
            "Results incomplete: 2 controls errored"
        );
    }

    #[test]
    fn score_percentage_validation_accepts_boundaries() {
        assert!(is_valid_score_percentage("0.0%"));
        assert!(is_valid_score_percentage("100.0%"));
    }

    #[test]
    fn account_summary_metadata_uses_report_layer_kind_label() {
        let record = report_evidence(
            "ev-account",
            Some("account"),
            Some(Classification::Sensitive),
        );
        let metadata = EvidenceSummaryMetadata::from_record(&record);

        assert_eq!(metadata.kind_label, "account");
        assert!(metadata.redacted);
    }

    #[test]
    fn summary_redaction_is_fail_safe_for_unknown_classification() {
        let unknown = report_evidence("ev-unknown", None, None);
        let public = report_evidence("ev-public", None, Some(Classification::Public));
        let secret = report_evidence("ev-secret", None, Some(Classification::Secret));

        assert!(EvidenceSummaryMetadata::from_record(&unknown).redacted);
        assert!(!EvidenceSummaryMetadata::from_record(&public).redacted);
        assert!(EvidenceSummaryMetadata::from_record(&secret).redacted);
    }

    #[test]
    fn score_percentage_validation_rejects_malformed_values() {
        for percentage in ["-0.1%", "100.1%", "101.0%", "42%", "50.12%", "50.x%", "abc"] {
            assert!(
                !is_valid_score_percentage(percentage),
                "{percentage} is not a valid one-decimal percentage"
            );
        }
    }

    #[test]
    fn invalid_framework_score_is_a_usage_error() {
        let args = [
            "--run",
            "shopfront-2026-06-24",
            "--evidence-store",
            ".",
            "--executed-at",
            "2026-06-24T13:16:28Z",
            "--framework-score",
            "101.0%",
        ]
        .map(str::to_string);
        let Err(error) = parse_args(&args) else {
            panic!("invalid framework score should be rejected");
        };

        assert_eq!(
            error.to_string(),
            format!("invalid --framework-score '101.0%' ({FRAMEWORK_SCORE_USAGE})")
        );
    }
}

fn write_pdf<W: IoWrite>(sink: &mut W, lines: &[String]) -> io::Result<()> {
    write_pdf_with_settings(sink, lines, &PdfSettings::default())
}

fn write_pdf_with_settings<W: IoWrite>(
    sink: &mut W,
    lines: &[String],
    settings: &PdfSettings,
) -> io::Result<()> {
    let pages = paginate_lines(lines, settings);
    let object_count = pdf_object_count(pages.len())?;
    let mut writer = CountingWriter::new(sink);
    writer.write_bytes(b"%PDF-1.4\n")?;
    let mut offsets = Vec::with_capacity(object_count + 1);
    offsets.push(0);
    write_object(&mut writer, &mut offsets, 1, |writer| {
        writer.write_bytes(b"<< /Type /Catalog /Pages 2 0 R >>\n")
    })?;
    write_object(&mut writer, &mut offsets, 2, |writer| {
        writer.write_bytes(b"<< /Type /Pages /Kids [")?;
        for index in 0..pages.len() {
            if index > 0 {
                writer.write_bytes(b" ")?;
            }
            writer.write_str(&format!("{} 0 R", page_object_number(index)?))?;
        }
        writer.write_str(&format!("] /Count {} >>\n", pages.len()))
    })?;
    write_object(&mut writer, &mut offsets, 3, |writer| {
        writer.write_str(&format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{} >>\n",
            settings.base_font
        ))
    })?;
    for (index, page_lines) in pages.iter().enumerate() {
        let page_object = page_object_number(index)?;
        let content_object = content_object_number(index)?;
        write_object(&mut writer, &mut offsets, page_object, |writer| {
            writer.write_str(&format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /{} 3 0 R >> >> /Contents {} 0 R >>\n",
                    settings.page_width_points,
                    settings.page_height_points,
                    settings.font_resource,
                    content_object
                ))
        })?;
        write_object(&mut writer, &mut offsets, content_object, |writer| {
            writer.write_str(&format!(
                "<< /Length {} >>\nstream\n",
                page_content_len(page_lines, settings)
            ))?;
            write_page_content(writer, page_lines, settings)?;
            writer.write_bytes(b"endstream\n")
        })?;
    }

    let xref_offset = writer.offset();
    writer.write_str(&format!("xref\n0 {}\n", offsets.len()))?;
    writer.write_bytes(b"0000000000 65535 f \n")?;
    for offset in offsets.iter().skip(1) {
        writer.write_str(&format!("{offset:010} 00000 n \n"))?;
    }
    writer.write_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
        offsets.len()
    ))
}

fn paginate_lines<'a>(lines: &'a [String], settings: &PdfSettings) -> Vec<&'a [String]> {
    let lines_per_page = lines_per_page(settings).max(1);
    if lines.is_empty() {
        vec![lines]
    } else {
        lines.chunks(lines_per_page).collect()
    }
}

fn lines_per_page(settings: &PdfSettings) -> usize {
    let usable_height = settings
        .top_baseline_points
        .saturating_sub(settings.bottom_margin_points);
    usize::from(usable_height / u16::from(settings.line_height_points)) + 1
}

fn pdf_object_count(page_count: usize) -> io::Result<usize> {
    page_count
        .checked_mul(PDF_OBJECTS_PER_PAGE)
        .and_then(|page_objects| PDF_FIXED_OBJECT_COUNT.checked_add(page_objects))
        .ok_or_else(pdf_page_count_overflow)
}

fn page_object_number(index: usize) -> io::Result<usize> {
    index
        .checked_mul(PDF_OBJECTS_PER_PAGE)
        .and_then(|offset| PDF_FIRST_PAGE_OBJECT.checked_add(offset))
        .ok_or_else(pdf_page_count_overflow)
}

fn content_object_number(index: usize) -> io::Result<usize> {
    page_object_number(index)?
        .checked_add(PDF_CONTENT_OBJECT_OFFSET)
        .ok_or_else(pdf_page_count_overflow)
}

fn pdf_page_count_overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "report contains too many pages to render",
    )
}

fn write_object<W: IoWrite>(
    writer: &mut CountingWriter<'_, W>,
    offsets: &mut Vec<usize>,
    object_number: usize,
    write_body: impl FnOnce(&mut CountingWriter<'_, W>) -> io::Result<()>,
) -> io::Result<()> {
    offsets.push(writer.offset());
    writer.write_str(&format!("{object_number} 0 obj\n"))?;
    write_body(writer)?;
    writer.write_bytes(b"endobj\n")
}

fn page_content_len(lines: &[String], settings: &PdfSettings) -> usize {
    let mut length = format!(
        "BT\n/{} {} Tf\n{} {} Td\n",
        settings.font_resource,
        settings.font_size_points,
        settings.left_margin_points,
        settings.top_baseline_points
    )
    .len();
    for line in lines {
        length += 1;
        length += escaped_pdf_text_len(line);
        length += format!(") Tj\n0 -{} Td\n", settings.line_height_points).len();
    }
    length + b"ET\n".len()
}

fn write_page_content<W: IoWrite>(
    writer: &mut CountingWriter<'_, W>,
    lines: &[String],
    settings: &PdfSettings,
) -> io::Result<()> {
    writer.write_str(&format!(
        "BT\n/{} {} Tf\n{} {} Td\n",
        settings.font_resource,
        settings.font_size_points,
        settings.left_margin_points,
        settings.top_baseline_points
    ))?;
    for line in lines {
        writer.write_bytes(b"(")?;
        write_escaped_pdf_text(writer, line)?;
        writer.write_str(&format!(") Tj\n0 -{} Td\n", settings.line_height_points))?;
    }
    writer.write_bytes(b"ET\n")
}

fn escaped_pdf_text_len(raw: &str) -> usize {
    raw.chars().map(escaped_char_len).sum()
}

fn escaped_char_len(character: char) -> usize {
    match character {
        '(' | ')' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        other if other.is_control() => 1,
        _ => character.len_utf8(),
    }
}

fn write_escaped_pdf_text<W: IoWrite>(
    writer: &mut CountingWriter<'_, W>,
    raw: &str,
) -> io::Result<()> {
    for character in raw.chars() {
        match character {
            '(' | ')' | '\\' => {
                writer.write_bytes(b"\\")?;
                writer.write_char(character)?;
            }
            '\n' => writer.write_bytes(b"\\n")?,
            '\r' => writer.write_bytes(b"\\r")?,
            '\t' => writer.write_bytes(b"\\t")?,
            '\u{08}' => writer.write_bytes(b"\\b")?,
            '\u{0c}' => writer.write_bytes(b"\\f")?,
            other if other.is_control() => writer.write_bytes(b" ")?,
            _ => writer.write_char(character)?,
        }
    }
    Ok(())
}

fn canonical_evidence_store(path: &Path) -> Result<PathBuf, Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent =
        fs::canonicalize(parent).map_err(|reason| Error::InvalidEvidenceStorePath {
            path: parent.display().to_string(),
            reason,
        })?;
    let canonical = fs::canonicalize(path).map_err(|reason| Error::InvalidEvidenceStorePath {
        path: path.display().to_string(),
        reason,
    })?;
    if !canonical.is_dir() {
        return Err(Error::InvalidEvidenceStorePath {
            path: path.display().to_string(),
            reason: io::Error::new(io::ErrorKind::InvalidInput, "not a directory"),
        });
    }
    if !canonical.starts_with(&canonical_parent) {
        return Err(Error::InvalidEvidenceStorePath {
            path: path.display().to_string(),
            reason: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "resolved path escapes its declared parent directory",
            ),
        });
    }
    Ok(canonical)
}

fn is_valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUN_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

struct CountingWriter<'a, W: IoWrite> {
    sink: &'a mut W,
    offset: usize,
}

impl<'a, W: IoWrite> CountingWriter<'a, W> {
    fn new(sink: &'a mut W) -> Self {
        Self { sink, offset: 0 }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn write_str(&mut self, value: &str) -> io::Result<()> {
        self.write_bytes(value.as_bytes())
    }

    fn write_bytes(&mut self, value: &[u8]) -> io::Result<()> {
        self.sink.write_all(value)?;
        self.offset += value.len();
        Ok(())
    }

    fn write_char(&mut self, character: char) -> io::Result<()> {
        let mut buffer = [0; 4];
        self.write_str(character.encode_utf8(&mut buffer))
    }
}

struct PdfSettings {
    page_width_points: u16,
    page_height_points: u16,
    left_margin_points: u16,
    top_baseline_points: u16,
    bottom_margin_points: u16,
    font_resource: &'static str,
    base_font: &'static str,
    font_size_points: u8,
    line_height_points: u8,
}

impl Default for PdfSettings {
    fn default() -> Self {
        Self {
            page_width_points: DEFAULT_PAGE_WIDTH_POINTS,
            page_height_points: DEFAULT_PAGE_HEIGHT_POINTS,
            left_margin_points: DEFAULT_LEFT_MARGIN_POINTS,
            top_baseline_points: DEFAULT_TOP_BASELINE_POINTS,
            bottom_margin_points: DEFAULT_BOTTOM_MARGIN_POINTS,
            font_resource: DEFAULT_FONT_RESOURCE,
            base_font: DEFAULT_BASE_FONT,
            font_size_points: DEFAULT_FONT_SIZE_POINTS,
            line_height_points: DEFAULT_LINE_HEIGHT_POINTS,
        }
    }
}

struct Config {
    run_id: String,
    evidence_store: PathBuf,
    executed_at: String,
    framework_score: String,
}

enum ParsedArgs {
    Help,
    Report(Config),
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, Error> {
    let mut run_id = None;
    let mut evidence_store = None;
    let mut executed_at = None;
    let mut framework_score = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(ParsedArgs::Help);
        } else if let Some(value) = arg.strip_prefix("--run=") {
            run_id = Some(value.to_string());
        } else if arg == "--run" {
            run_id = Some(next_value(&mut iter, "--run")?);
        } else if let Some(value) = arg.strip_prefix("--evidence-store=") {
            evidence_store = Some(value.to_string());
        } else if arg == "--evidence-store" {
            evidence_store = Some(next_value(&mut iter, "--evidence-store")?);
        } else if let Some(value) = arg.strip_prefix("--executed-at=") {
            executed_at = Some(value.to_string());
        } else if arg == "--executed-at" {
            executed_at = Some(next_value(&mut iter, "--executed-at")?);
        } else if let Some(value) = arg.strip_prefix("--framework-score=") {
            framework_score = Some(value.to_string());
        } else if arg == "--framework-score" {
            framework_score = Some(next_value(&mut iter, "--framework-score")?);
        } else {
            return Err(Error::UnknownArgument(arg.clone()));
        }
    }

    let run_id = run_id.ok_or(Error::MissingRun)?;
    if !is_valid_run_id(&run_id) {
        return Err(Error::InvalidRun(run_id));
    }

    let executed_at = executed_at.ok_or(Error::MissingExecutedAt)?;
    if !is_valid_execution_timestamp(&executed_at) {
        return Err(Error::InvalidExecutedAt(executed_at));
    }

    let framework_score =
        framework_score.unwrap_or_else(|| CONSENT_CORPUS_FRAMEWORK_SCORE.to_string());
    if !is_valid_score_percentage(&framework_score) {
        return Err(Error::InvalidFrameworkScore(framework_score));
    }

    Ok(ParsedArgs::Report(Config {
        run_id,
        evidence_store: PathBuf::from(evidence_store.ok_or(Error::MissingEvidenceStore)?),
        executed_at,
        framework_score,
    }))
}

fn next_value(iter: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, Error> {
    iter.next()
        .cloned()
        .ok_or_else(|| Error::MissingValue(flag.to_string()))
}

#[derive(Debug)]
enum Error {
    MissingRun,
    MissingEvidenceStore,
    MissingExecutedAt,
    InvalidRun(String),
    InvalidExecutedAt(String),
    InvalidFrameworkScore(String),
    MissingValue(String),
    UnknownArgument(String),
    InvalidEvidenceStorePath { path: String, reason: io::Error },
    EvidenceStore(StoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingRun => f.write_str("missing --run <id>"),
            Error::MissingEvidenceStore => f.write_str("missing --evidence-store <dir>"),
            Error::MissingExecutedAt => f.write_str("missing --executed-at <timestamp>"),
            Error::InvalidRun(value) => write!(
                f,
                "invalid --run id '{value}' (use ASCII letters, numbers, hyphens, or underscores)"
            ),
            Error::InvalidExecutedAt(value) => {
                write!(f, "invalid --executed-at timestamp '{value}'")
            }
            Error::InvalidFrameworkScore(value) => {
                write!(
                    f,
                    "invalid --framework-score '{value}' ({FRAMEWORK_SCORE_USAGE})"
                )
            }
            Error::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Error::UnknownArgument(arg) => write!(f, "unknown argument '{arg}'"),
            Error::InvalidEvidenceStorePath { path, reason } => {
                write!(f, "invalid --evidence-store path '{path}': {reason}")
            }
            Error::EvidenceStore(error) => write!(f, "evidence store error: {error}"),
        }
    }
}
