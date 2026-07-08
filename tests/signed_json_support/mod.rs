// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-97 signed-JSON export acceptance tests.
//!
//! Holds the non-production signing seed that keeps the signed artifact
//! byte-stable across runs, plus small readers over the compact canonical JSON
//! the exporter emits. Each `signed_json_*` test binary pulls in what it needs;
//! not every binary uses every helper.
#![allow(dead_code)]

use sovri_agent::matrix::Corpus;
use sovri_sdk::{ControlResult, Status};

/// A fixed, non-production Ed25519 signing seed.
///
/// Committed only so the signed export is deterministic and snapshot-testable.
/// It signs test fixtures and nothing else — never a real compliance artifact.
pub const FIXTURE_SIGNING_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const RUN_ID: &str = "shopfront-2026-06-24";
const FRAMEWORK: &str = "gdpr-eprivacy";
const FRAMEWORK_VERSION: &str = "2016-679";
const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const CONTROL: &str = "consent.tracker.prior-consent";
const CONTROL_TITLE: &str = "Prior consent for tracker access";
const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
const CONTROL_SEVERITY: &str = "major";
const CONTROL_WEIGHT: u32 = 8;
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const EVIDENCE_ID: &str = "ev-0001";
const EXECUTION_METADATA: &str = "engine_version=0.3.0";

fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity(CONTROL_SEVERITY)
        .weight(CONTROL_WEIGHT)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata(EXECUTION_METADATA);
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// Returns the fixed `shopfront-2026-06-24` consent corpus used by MAT-97 signed
/// JSON acceptance tests.
#[must_use]
pub fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            CONTROL_SEVERITY,
            CONTROL_WEIGHT,
            CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
        .with_evidence(EVIDENCE_ID, "dist/main.js")
}

/// Returns true when the compact JSON document carries a top-level-visible
/// member named `name` (matched as `"name":`).
///
/// Adequate for the exporter's canonical, space-free output where a member name
/// appears exactly where the document places it.
#[must_use]
pub fn has_member(doc: &str, name: &str) -> bool {
    doc.contains(&format!("\"{name}\":"))
}

/// Returns the string value of the first `"name":"..."` member in a compact
/// JSON document, or `None` if the member is absent or not a string.
///
/// Reads until the closing unescaped quote. The exporter emits no whitespace
/// between tokens, so the `"name":"` anchor is exact.
#[must_use]
pub fn string_member(doc: &str, name: &str) -> Option<String> {
    let anchor = format!("\"{name}\":\"");
    let start = doc.find(&anchor)? + anchor.len();
    let mut out = String::new();
    let mut chars = doc[start..].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                out.push('\\');
                out.push(chars.next()?);
            }
            '"' => return Some(out),
            _ => out.push(ch),
        }
    }
    None
}

/// Returns the JSON value of the member `name` — the balanced `{...}` object or
/// `[...]` array that follows `"name":` in the compact document — so a test can
/// scope an assertion to one section (a payload array, the verification object,
/// and so on).
///
/// Nesting depth is tracked through string values, so the matching close
/// delimiter, not a brace or bracket inside a string, ends the slice. Handles
/// both object and array values, which is why no separate array scoper is needed.
/// Standard-library only.
///
/// # Panics
///
/// Panics when the document carries no `"name":` member, so a test that scopes a
/// missing section fails with a clear message.
#[must_use]
pub fn section_value<'a>(doc: &'a str, name: &str) -> &'a str {
    let anchor = format!("\"{name}\":");
    let start = doc
        .find(&anchor)
        .unwrap_or_else(|| panic!("the document has a {name:?} member"))
        + anchor.len();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in doc[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return &doc[start..start + offset + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }
    &doc[start..]
}
