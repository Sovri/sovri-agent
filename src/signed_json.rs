// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Signed JSON compliance export (MAT-97).
//!
//! Serializes the persisted compliance [`Corpus`] into a versioned, canonical
//! JSON document and signs it with an offline-verifiable Ed25519 signature. The
//! document carries three members: a `payload` (the compliance data), a
//! `verification` block (algorithm, key id, embedded public key), and a
//! top-level `signature` over the canonical bytes of the first two.
//!
//! Canonicalization is deterministic and standard-library only — object keys in
//! lexicographic order, fixed string escaping, integers verbatim — so the same
//! corpus and key always produce byte-identical output. The signature covers the
//! SHA-256 digest (MAT-93, via [`sovri_sdk::content_digest`]) of the canonical
//! `payload` + `verification` bytes, so the embedded key and key id are
//! themselves signed and cannot be swapped without breaking verification.
//! Ed25519 comes from `ed25519-dalek` (ADR-031); the curve is not hand-rolled
//! and no private key material is ever emitted.

use crate::matrix::Corpus;
use ed25519_dalek::{Signer, SigningKey};
use sovri_sdk::{content_digest, ControlResult, Status};
use std::fmt;

/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";
/// The supported schema version the verifier gates on.
const SCHEMA_VERSION: i64 = 1;
/// The signature algorithm the verification block names.
const ALGORITHM: &str = "Ed25519";
/// Hex length of the truncated public-key fingerprint carried as the key id.
const KEY_ID_HEX_LEN: usize = 16;

/// Exports the compliance `corpus` as a signed JSON document, signed with the
/// injected 32-byte Ed25519 seed.
///
/// Returns the canonical JSON text: a `payload` derived from the persisted
/// corpus, a `verification` block carrying the algorithm, a public-key
/// fingerprint, and the embedded public key, and a `signature` over the
/// canonical bytes of `payload` + `verification`. The same corpus and seed
/// always yield byte-identical output.
#[must_use]
pub fn export(corpus: &Corpus, signing_seed: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(signing_seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let scoped = corpus.scoped_results();
    let payload = Json::Object(vec![
        (
            "schema",
            Json::Object(vec![
                ("format", Json::Str(SCHEMA_FORMAT.to_owned())),
                ("schema_version", Json::Int(SCHEMA_VERSION)),
            ]),
        ),
        (
            "scan",
            Json::Object(vec![
                ("executed_at", Json::Str(corpus.executed_at().to_owned())),
                ("id", Json::Str(corpus.run_id().to_owned())),
            ]),
        ),
        ("frameworks", frameworks_array(&corpus.frameworks())),
        ("controls", id_array(&corpus.control_ids())),
        ("results", results_array(&scoped)),
        ("gaps", gaps_array(&scoped)),
        ("evidence", id_array(&corpus.evidence_ids())),
        ("scores", Json::Object(Vec::new())),
    ]);
    let verification = Json::Object(vec![
        ("algorithm", Json::Str(ALGORITHM.to_owned())),
        ("key_id", Json::Str(key_fingerprint(&public_key))),
        ("public_key", Json::Str(to_hex(&public_key))),
    ]);

    // The signature covers the canonical bytes of payload + verification, so the
    // embedded key and key id are authenticated and cannot be swapped silently.
    let mut members = vec![("payload", payload), ("verification", verification)];
    let signed_bytes = canonical_object(&members);
    let digest = content_digest(signed_bytes.as_bytes());
    let signature = signing_key.sign(digest.as_bytes());
    members.push(("signature", Json::Str(to_hex(&signature.to_bytes()))));

    canonical_object(&members)
}

/// Verifies a signed JSON `document`, returning `Ok(())` when it is a valid export
/// and an error describing the first check that failed.
///
/// Verification gates on the schema version first: the document must declare the
/// supported `payload.schema.schema_version` (currently `1`). A document whose
/// version member is absent, or carries a value other than the supported one, is
/// rejected before any further check, so an unknown schema is a distinct failure
/// that a later signature check builds on rather than conflates with.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedVersion`] when the document declares no
/// `payload.schema.schema_version`, or one other than the supported version.
pub fn verify(document: &str) -> Result<(), VerifyError> {
    if declared_schema_version(document) != Some(SCHEMA_VERSION) {
        return Err(VerifyError::UnsupportedVersion);
    }
    Ok(())
}

/// Reads the `schema_version` integer a compact export `document` declares, or
/// `None` when the member is absent or not an unquoted integer.
///
/// Scans for the `"schema_version":` key and parses the unquoted digit run that
/// follows, matching how the exporter emits the version; a quoted value is a
/// string, not an integer version, and yields `None`.
fn declared_schema_version(document: &str) -> Option<i64> {
    let anchor = "\"schema_version\":";
    let start = document.find(anchor)? + anchor.len();
    let digits: String = document[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Why a signed export failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The document declares no supported schema version — its
    /// `payload.schema.schema_version` member is absent or carries a value the
    /// verifier does not support — so it cannot be read as a known export.
    UnsupportedVersion,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                f.write_str("the export declares no supported schema version")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// A minimal JSON value the canonical serializer emits.
enum Json {
    /// A JSON string, escaped on output.
    Str(String),
    /// A JSON integer, emitted verbatim.
    Int(i64),
    /// A JSON array; its elements are emitted in the order given.
    Array(Vec<Json>),
    /// A JSON object; its members are sorted by key on output.
    Object(Vec<(&'static str, Json)>),
}

/// Builds a JSON array of single-id records — one `{ "id": <id> }` per stable id.
///
/// The controls and evidence sections each carry this minimal record so every
/// entry traces back to the corpus by its stable id; later scenarios add the
/// remaining per-record fields.
fn id_array(ids: &[&str]) -> Json {
    Json::Array(
        ids.iter()
            .map(|&id| Json::Object(vec![("id", Json::Str(id.to_owned()))]))
            .collect(),
    )
}

/// Builds the `frameworks` section — one record per framework carrying its stable
/// id, catalog version, and source URL, so a consumer can pin the exact catalog
/// version the results were derived against.
fn frameworks_array(frameworks: &[(&str, &str, &str)]) -> Json {
    Json::Array(
        frameworks
            .iter()
            .map(|&(id, version, source_url)| {
                Json::Object(vec![
                    ("id", Json::Str(id.to_owned())),
                    ("version", Json::Str(version.to_owned())),
                    ("source_url", Json::Str(source_url.to_owned())),
                ])
            })
            .collect(),
    )
}

/// Builds the `results` section — one record per control result, carrying the
/// stable control and rule ids that trace it back to the corpus.
fn results_array(scoped: &[(Option<&str>, &ControlResult)]) -> Json {
    Json::Array(
        scoped
            .iter()
            .map(|&(_, result)| result_member(result))
            .collect(),
    )
}

/// Builds the `gaps` section — one record per compliance gap: a framework-scoped
/// result that failed or warned and so requires review. A passing, skipped, or
/// unscoped result is not a gap.
fn gaps_array(scoped: &[(Option<&str>, &ControlResult)]) -> Json {
    Json::Array(
        scoped
            .iter()
            .filter(|(framework, result)| framework.is_some() && is_gap(result.status()))
            .map(|&(_, result)| result_member(result))
            .collect(),
    )
}

/// Builds the JSON record the results and gaps sections share — a stable derived
/// id (`{control_id}:{rule_id}`), the control and rule ids it is composed from, and
/// the status label (`PASS`, `FAIL`, `WARNING`, `SKIPPED`, or `ERROR`), the same
/// label the matrix export renders. The id is derived only from the record's own
/// stable corpus keys, so re-exporting the same corpus yields the same id.
fn result_member(result: &ControlResult) -> Json {
    Json::Object(vec![
        ("control_id", Json::Str(result.control_id().to_owned())),
        (
            "id",
            Json::Str(format!("{}:{}", result.control_id(), result.rule_id())),
        ),
        ("rule_id", Json::Str(result.rule_id().to_owned())),
        ("status", Json::Str(result.status().label().to_owned())),
    ])
}

/// Whether a result of `status` is a compliance gap — a failed or warned outcome
/// the gaps section carries for review.
fn is_gap(status: Status) -> bool {
    matches!(status, Status::Fail | Status::Warning)
}

/// Serializes a set of object members as a canonical JSON object string.
fn canonical_object(members: &[(&'static str, Json)]) -> String {
    let mut out = String::new();
    write_object(&mut out, members);
    out
}

/// Writes `members` as a canonical JSON object into `out`: keys in lexicographic
/// order, no insignificant whitespace, so the bytes depend only on the values.
fn write_object(out: &mut String, members: &[(&'static str, Json)]) {
    let mut ordered: Vec<&(&'static str, Json)> = members.iter().collect();
    ordered.sort_unstable_by_key(|entry| entry.0);
    out.push('{');
    for (index, (key, value)) in ordered.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, value);
    }
    out.push('}');
}

/// Writes a single JSON value into `out`.
fn write_value(out: &mut String, value: &Json) {
    match value {
        Json::Str(text) => write_string(out, text),
        Json::Int(number) => out.push_str(&number.to_string()),
        Json::Array(items) => write_array(out, items),
        Json::Object(members) => write_object(out, members),
    }
}

/// Writes `items` as a canonical JSON array into `out`, emitting the elements in
/// the order given — the caller supplies them in a stable, corpus-derived order,
/// so the bytes depend only on the values.
fn write_array(out: &mut String, items: &[Json]) {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_value(out, item);
    }
    out.push(']');
}

/// Writes `text` as a quoted, escaped JSON string into `out`.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                let code = u32::from(control);
                out.push_str("\\u00");
                out.push(hex_digit((code >> 4) & 0xf));
                out.push(hex_digit(code & 0xf));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Returns the `sha256:`-prefixed, truncated fingerprint of a public key, the
/// value the verification block carries as its key id.
fn key_fingerprint(public_key: &[u8; 32]) -> String {
    let hex = content_digest(public_key).hex();
    let mut id = String::from("sha256:");
    id.push_str(&hex[..KEY_ID_HEX_LEN]);
    id
}

/// Encodes bytes as lowercase hexadecimal.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(hex_digit(u32::from(byte) >> 4));
        out.push(hex_digit(u32::from(byte) & 0x0f));
    }
    out
}

/// Maps a nibble (`0..=15`) to its lowercase hexadecimal digit.
fn hex_digit(nibble: u32) -> char {
    char::from_digit(nibble, 16).unwrap_or('0')
}
