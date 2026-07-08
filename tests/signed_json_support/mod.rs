// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for the MAT-97 signed-JSON export acceptance tests.
//!
//! Holds the non-production signing seed that keeps the signed artifact
//! byte-stable across runs, plus small readers over the compact canonical JSON
//! the exporter emits. Each `signed_json_*` test binary pulls in what it needs;
//! not every binary uses every helper.
#![allow(dead_code)]

/// A fixed, non-production Ed25519 signing seed.
///
/// Committed only so the signed export is deterministic and snapshot-testable.
/// It signs test fixtures and nothing else — never a real compliance artifact.
pub const FIXTURE_SIGNING_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

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
