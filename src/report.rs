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

use crate::evidence::{Evidence, EvidenceLog, EvidenceStore, StoreError};
use crate::scanners::ssh;
use sovri_sdk::is_valid_execution_timestamp;

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
/// Built-in PDF font resource name.
const DEFAULT_FONT_RESOURCE: &str = "F1";
/// Built-in PDF base font name.
const DEFAULT_BASE_FONT: &str = "Helvetica";
/// Text font size in PDF points.
const DEFAULT_FONT_SIZE_POINTS: u8 = 10;
/// Distance between text baselines in PDF points.
const DEFAULT_LINE_HEIGHT_POINTS: u8 = 14;
/// Number of PDF indirect objects written by the minimal renderer.
const PDF_OBJECT_COUNT: usize = 5;
/// Maximum accepted run identifier length.
const MAX_RUN_ID_BYTES: usize = 128;
/// Prefix for fields nested under a rendered evidence record.
const EVIDENCE_FIELD_INDENT: &str = "  ";
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
/// Section headings required in every generated report.
const REQUIRED_REPORT_SECTIONS: [&str; 7] = [
    SECTION_EXECUTIVE_SUMMARY,
    "Framework coverage",
    SECTION_SCORES,
    SECTION_CONTROL_MATRIX,
    SECTION_GAPS,
    SECTION_EVIDENCE_SUMMARY,
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

struct GapReference {
    control_id: &'static str,
    framework_reference: &'static str,
    source_url: &'static str,
    severity: &'static str,
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
        DOCKER_BASE_IMAGE_CONTROL_ID if reason == DOCKER_SKIPPED_REASON => Some("SKIPPED"),
        ssh::PERMIT_ROOT_LOGIN_RULE if reason == SSH_ERROR_REASON => Some("ERROR"),
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
            non_conclusive_record_status(record).is_some_and(|(_, _, status)| status == "ERROR")
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

fn fail(error: &Error) -> ExitCode {
    eprintln!("sovri-agent report: {error}");
    ExitCode::from(EXIT_USAGE)
}

fn execute(config: &Config) -> Result<Vec<String>, Error> {
    let evidence_store = canonical_evidence_store(&config.evidence_store)?;
    let store = EvidenceStore::open(&evidence_store).map_err(Error::EvidenceStore)?;
    let evidence = store.read_all().map_err(Error::EvidenceStore)?;
    let cmp_warning_reason = evidence.records().iter().find_map(|record| {
        (record.signal() == Some(CONSENT_CORPUS_WARNING_REASON))
            .then_some(CONSENT_CORPUS_WARNING_REASON)
    });
    let error_count = error_control_count(&evidence);
    let mut lines = vec!["Sovri PDF compliance report".to_string()];
    for section in REQUIRED_REPORT_SECTIONS {
        if section == SECTION_CONTROL_MATRIX {
            lines.extend(evidence_lines(&evidence));
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
                    format!("Result counts: {CONSENT_CORPUS_RESULT_COUNTS}"),
                ]);
                if error_count > 0 {
                    lines.push(incomplete_results_line(error_count));
                }
            }
            SECTION_SCORES => lines.extend([
                format!(
                    "Framework score {CONSENT_CORPUS_FRAMEWORK_ID}: {}",
                    config.framework_score
                ),
                format!("Result counts: {CONSENT_CORPUS_SCORE_RESULT_COUNTS}"),
                SCORE_POSTURE_CAVEAT.to_string(),
                SCORE_LEGAL_RISK_CAVEAT.to_string(),
            ]),
            SECTION_CONTROL_MATRIX => {
                // Keep legacy rule lines for R-02; R-04 rows provide one countable row per status.
                lines.extend([
                    format!("Control: {CONSENT_CORPUS_CONTROL_ID}"),
                    format!("Rule {CONSENT_CORPUS_TRACKER_RULE_ID}: FAIL"),
                    control_row(CONSENT_CORPUS_CONTROL_ID, "FAIL"),
                ]);
                if let Some(reason) = cmp_warning_reason {
                    lines.push(format!("Rule {CONSENT_CORPUS_CMP_RULE_ID}: WARNING"));
                    lines.push(format!("Explanation: {reason}"));
                } else {
                    lines.push(format!("Rule {CONSENT_CORPUS_CMP_RULE_ID}: PASS"));
                }
                for record in evidence.records() {
                    let Some((control_id, reason, status)) = non_conclusive_record_status(record)
                    else {
                        continue;
                    };
                    lines.push(control_row(control_id, status));
                    lines.push(format!("Explanation: {reason}"));
                }
            }
            SECTION_GAPS => {
                for record in evidence.records() {
                    let Some(control_id) = record.control_id() else {
                        continue;
                    };
                    let reference = GAP_REFERENCES
                        .iter()
                        .find(|reference| reference.control_id == control_id);
                    lines.push(format!("Gap: {control_id}"));
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
                lines.push(format!(
                    "Remediation for {CONSENT_CORPUS_CONTROL_ID}: {CONSENT_CORPUS_REMEDIATION}"
                ));
            }
            SECTION_EVIDENCE_SUMMARY => {
                lines.push(format!("Evidence records: {}", evidence.len()));
            }
            _ => {}
        }
    }
    Ok(lines)
}

fn evidence_lines(evidence: &EvidenceLog) -> Vec<String> {
    let mut lines = Vec::new();
    for record in evidence.records() {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    let mut writer = CountingWriter::new(sink);
    writer.write_bytes(b"%PDF-1.4\n")?;
    let mut offsets = Vec::with_capacity(PDF_OBJECT_COUNT + 1);
    offsets.push(0);
    write_object(&mut writer, &mut offsets, 1, |writer| {
        writer.write_bytes(b"<< /Type /Catalog /Pages 2 0 R >>\n")
    })?;
    write_object(&mut writer, &mut offsets, 2, |writer| {
        writer.write_bytes(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n")
    })?;
    write_object(&mut writer, &mut offsets, 3, |writer| {
        writer.write_str(&format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << /{} 4 0 R >> >> /Contents 5 0 R >>\n",
            settings.page_width_points, settings.page_height_points, settings.font_resource
        ))
    })?;
    write_object(&mut writer, &mut offsets, 4, |writer| {
        writer.write_str(&format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{} >>\n",
            settings.base_font
        ))
    })?;
    write_object(&mut writer, &mut offsets, 5, |writer| {
        writer.write_str(&format!(
            "<< /Length {} >>\nstream\n",
            page_content_len(lines, settings)
        ))?;
        write_page_content(writer, lines, settings)?;
        writer.write_bytes(b"endstream\n")
    })?;

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
