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

use crate::evidence::{EvidenceStore, StoreError};
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

/// The `report` command help text.
const HELP: &str = "\
usage: sovri-agent report --run <id> --evidence-store <dir> --executed-at <timestamp>

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
    let mut lines = vec![
        "Sovri PDF compliance report".to_string(),
        format!("Run: {}", config.run_id),
        format!("Generated date: {}", config.executed_at),
        format!("Evidence records: {}", evidence.len()),
    ];
    for record in evidence.records() {
        lines.push(format!("Evidence: {}", record.id()));
        if let Some(control_id) = record.control_id() {
            lines.push(format!("  Control: {control_id}"));
        }
        lines.push(format!("  Locator: {}", record.locator()));
        if let Some(signal) = record.signal() {
            lines.push(format!("  Signal: {signal}"));
        }
        lines.push(format!("  Integrity: {}", record.content_hash()));
    }
    Ok(lines)
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
}

enum ParsedArgs {
    Help,
    Report(Config),
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, Error> {
    let mut run_id = None;
    let mut evidence_store = None;
    let mut executed_at = None;

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

    Ok(ParsedArgs::Report(Config {
        run_id,
        evidence_store: PathBuf::from(evidence_store.ok_or(Error::MissingEvidenceStore)?),
        executed_at,
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
            Error::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Error::UnknownArgument(arg) => write!(f, "unknown argument '{arg}'"),
            Error::InvalidEvidenceStorePath { path, reason } => {
                write!(f, "invalid --evidence-store path '{path}': {reason}")
            }
            Error::EvidenceStore(error) => write!(f, "evidence store error: {error}"),
        }
    }
}
