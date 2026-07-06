// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Deterministic PDF compliance report rendering.
//!
//! The report command reads the persisted evidence store and writes a minimal
//! text-only PDF to standard output. It uses the built-in Helvetica font and an
//! uncompressed content stream, so the output stays deterministic and the agent
//! keeps its zero third-party runtime dependency posture.

use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use crate::evidence::{EvidenceStore, StoreError};

/// Exit code when the report was produced successfully.
const EXIT_OK: u8 = 0;
/// Exit code for usage or input errors.
const EXIT_USAGE: u8 = 64;

/// The `report` command help text.
const HELP: &str = "\
usage: sovri-agent report --run <id> --evidence-store <dir> --executed-at <timestamp>

Generate a deterministic PDF compliance report from a persisted evidence store.
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
        Ok(pdf) => {
            if let Err(error) = io::stdout().lock().write_all(&pdf) {
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

fn execute(config: &Config) -> Result<Vec<u8>, Error> {
    let store = EvidenceStore::open(&config.evidence_store).map_err(Error::EvidenceStore)?;
    let evidence = store.read_all().map_err(Error::EvidenceStore)?;
    let lines = vec![
        "Sovri PDF compliance report".to_string(),
        format!("Run: {}", config.run_id),
        format!("Generated date: {}", config.executed_at),
        format!("Evidence records: {}", evidence.len()),
    ];
    Ok(render_pdf(&lines))
}

fn render_pdf(lines: &[String]) -> Vec<u8> {
    let content = page_content(lines);
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!(
            "<< /Length {} >>\nstream\n{}endstream",
            content.len(),
            content
        ),
    ];

    let mut output = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len() + 1);
    offsets.push(0);
    for (index, object) in objects.iter().enumerate() {
        offsets.push(output.len());
        output.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", index + 1, object).as_bytes());
    }

    let xref_offset = output.len();
    output.extend_from_slice(format!("xref\n0 {}\n", offsets.len()).as_bytes());
    output.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        output.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    output.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            offsets.len()
        )
        .as_bytes(),
    );
    output
}

fn page_content(lines: &[String]) -> String {
    let mut content = String::from("BT\n/F1 10 Tf\n72 760 Td\n");
    for line in lines {
        content.push('(');
        content.push_str(&escape_pdf_text(line));
        content.push_str(") Tj\n0 -14 Td\n");
    }
    content.push_str("ET\n");
    content
}

fn escape_pdf_text(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '(' | ')' | '\\' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

struct Config {
    run_id: String,
    evidence_store: String,
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

    Ok(ParsedArgs::Report(Config {
        run_id: run_id.ok_or(Error::MissingRun)?,
        evidence_store: evidence_store.ok_or(Error::MissingEvidenceStore)?,
        executed_at: executed_at.ok_or(Error::MissingExecutedAt)?,
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
    MissingValue(String),
    UnknownArgument(String),
    EvidenceStore(StoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingRun => f.write_str("missing --run <id>"),
            Error::MissingEvidenceStore => f.write_str("missing --evidence-store <dir>"),
            Error::MissingExecutedAt => f.write_str("missing --executed-at <timestamp>"),
            Error::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Error::UnknownArgument(arg) => write!(f, "unknown argument '{arg}'"),
            Error::EvidenceStore(error) => write!(f, "evidence store error: {error}"),
        }
    }
}
