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
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sovri_sdk::{
    content_digest, ControlResult, ControlScore, EnvironmentScore, FrameworkScore, ScoreRatio,
    Status,
};
use std::cmp::Ordering;
use std::fmt;

/// The self-describing schema format the export declares.
const SCHEMA_FORMAT: &str = "sovri.compliance-export/v1";
/// The supported schema version the verifier gates on.
const SCHEMA_VERSION: i64 = 1;
/// The signature algorithm the verification block names.
const ALGORITHM: &str = "Ed25519";
/// The top-level member that carries verification metadata.
const VERIFICATION_MEMBER_KEY: &str = "verification";
/// The verification-block member that carries the signature algorithm.
const ALGORITHM_MEMBER_KEY: &str = "algorithm";
/// The verification-block member that carries the embedded public key.
const PUBLIC_KEY_MEMBER_KEY: &str = "public_key";
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
    let frameworks = corpus.frameworks();
    let controls = corpus.controls();
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
        ("frameworks", frameworks_array(&frameworks)),
        ("controls", id_array(&corpus.control_ids())),
        ("results", results_array(&scoped)),
        ("gaps", gaps_array(&scoped, &controls, &frameworks)),
        ("evidence", id_array(&corpus.evidence_ids())),
        ("scores", scores_object(&corpus.environment_score())),
    ]);
    let verification = Json::Object(vec![
        (ALGORITHM_MEMBER_KEY, Json::Str(ALGORITHM.to_owned())),
        ("key_id", Json::Str(key_fingerprint(&public_key))),
        ("public_key", Json::Str(to_hex(&public_key))),
    ]);

    // The signature covers the canonical bytes of payload + verification, so the
    // embedded key and key id are authenticated and cannot be swapped silently.
    let mut members = vec![
        ("payload", payload),
        (VERIFICATION_MEMBER_KEY, verification),
    ];
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
/// supported `payload.schema.schema_version` (currently `1`). A version that is
/// absent or unsupported is rejected before any further check, a distinct failure
/// from a signature mismatch. It then gates on the declared
/// `verification.algorithm` (currently `Ed25519`) before checking the signature:
/// it reconstructs the canonical `payload` + `verification` bytes the signature
/// was computed over, recomputes their SHA-256 digest, and verifies the embedded
/// signature against the embedded public key. Any change to the payload or the
/// verification metadata after signing breaks the signature and is rejected.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedVersion`] when the document declares no
/// supported `payload.schema.schema_version`,
/// [`VerifyError::UnsupportedAlgorithm`] when it declares no supported
/// `verification.algorithm`, [`VerifyError::MissingVerificationKey`] when it
/// embeds no verification public key, or [`VerifyError::InvalidSignature`] when
/// the signature does not verify against the embedded public key over the
/// document's canonical payload and verification bytes.
pub fn verify(document: &str) -> Result<(), VerifyError> {
    if declared_schema_version(document) != Some(SCHEMA_VERSION) {
        return Err(VerifyError::UnsupportedVersion);
    }
    if declared_algorithm(document) != Some(ALGORITHM) {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    verify_signature(document)
}

/// Checks the Ed25519 signature of a schema- and algorithm-valid `document`.
///
/// Reconstructs the canonical `payload` + `verification` bytes the signature was
/// computed over — the document with its `signature` member removed — recomputes
/// their MAT-93 SHA-256 digest, decodes the embedded public key and signature from
/// hex, and verifies the signature over the digest. A document with no embedded
/// public key yields [`VerifyError::MissingVerificationKey`]; a malformed document,
/// a mis-sized key or signature, or a digest that does not match the signature all
/// yield [`VerifyError::InvalidSignature`].
fn verify_signature(document: &str) -> Result<(), VerifyError> {
    let (signed_bytes, signature_hex) =
        reconstruct_signed(document).ok_or(VerifyError::InvalidSignature)?;
    let public_key_hex =
        embedded_public_key(document).ok_or(VerifyError::MissingVerificationKey)?;
    let public_key: [u8; 32] = decode_fixed(public_key_hex).ok_or(VerifyError::InvalidSignature)?;
    let signature: [u8; 64] = decode_fixed(&signature_hex).ok_or(VerifyError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| VerifyError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature);
    let digest = content_digest(signed_bytes.as_bytes());
    verifying_key
        .verify_strict(digest.as_bytes(), &signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

/// Reconstructs the canonical bytes a signed export's signature was computed over —
/// `{"payload":…,"verification":…}` — and returns them with the signature hex.
///
/// The signed bytes are the document with its `signature` member removed. In the
/// canonical top-level object the keys sort `payload` < `signature` <
/// `verification`, so the signature member is `,"signature":"<hex>"`; stripping
/// that leading-comma member yields exactly the bytes that were signed. Returns
/// `None` when the document carries no signature member.
fn reconstruct_signed(document: &str) -> Option<(String, String)> {
    let anchor = "\"signature\":\"";
    let hex_start = document.find(anchor)? + anchor.len();
    let hex_len = document[hex_start..].find('"')?;
    let signature_hex = document[hex_start..hex_start + hex_len].to_owned();
    let member = format!(",\"signature\":\"{signature_hex}\"");
    let signed_bytes = document.replacen(&member, "", 1);
    Some((signed_bytes, signature_hex))
}

/// Returns the hex of the public key embedded in the document's `verification`
/// block, or `None` when the member is absent.
fn embedded_public_key(document: &str) -> Option<&str> {
    compact_object_string_member(verification_block(document)?, PUBLIC_KEY_MEMBER_KEY)
}

/// Reads the signature algorithm a compact export `document` declares, or `None`
/// when the member is absent.
fn declared_algorithm(document: &str) -> Option<&str> {
    compact_object_string_member(verification_block(document)?, ALGORITHM_MEMBER_KEY)
}

/// Returns the compact top-level `verification` object slice, or `None` when it is
/// absent or not a balanced object.
fn verification_block(document: &str) -> Option<&str> {
    compact_object_member(document, VERIFICATION_MEMBER_KEY)
}

/// Reads a compact JSON object member by key, or `None` when it is absent or
/// unbalanced.
fn compact_object_member<'a>(document: &'a str, member_key: &str) -> Option<&'a str> {
    let anchor = format!("\"{member_key}\":{{");
    let start = document.find(&anchor)? + anchor.len() - 1;
    let end = compact_value_end(document, start)?;
    Some(&document[start..=end])
}

/// Reads a direct compact JSON object string member by key, or `None` when the
/// direct member is absent or is not a string.
fn compact_object_string_member<'a>(object: &'a str, member_key: &str) -> Option<&'a str> {
    if object.as_bytes().first().copied()? != b'{' {
        return None;
    }

    let mut cursor = 1usize;
    while cursor < object.len() {
        match object.as_bytes().get(cursor).copied()? {
            b',' => {
                cursor += 1;
                continue;
            }
            b'"' => {}
            _ => return None,
        }

        let (key, key_end) = compact_string_at(object, cursor)?;
        if object.as_bytes().get(key_end + 1).copied()? != b':' {
            return None;
        }
        let value_start = key_end + 2;
        let value_end = compact_value_end(object, value_start)?;
        if key == member_key {
            let (value, string_end) = compact_string_at(object, value_start)?;
            return (string_end == value_end).then_some(value);
        }
        cursor = value_end + 1;
    }

    None
}

/// Reads the compact JSON string starting at `start`, returning its raw value and
/// closing quote byte index.
fn compact_string_at(document: &str, start: usize) -> Option<(&str, usize)> {
    if document.as_bytes().get(start).copied()? != b'"' {
        return None;
    }

    let mut escaped = false;
    for (offset, ch) in document[start + 1..].char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            let end = start + 1 + offset;
            return Some((&document[start + 1..end], end));
        }
    }

    None
}

/// Returns the byte index where the compact JSON value starting at `start` ends.
fn compact_value_end(document: &str, start: usize) -> Option<usize> {
    match document.as_bytes().get(start).copied()? {
        b'{' | b'[' => return compact_container_end(document, start),
        b'"' => return compact_string_at(document, start).map(|(_, end)| end),
        _ => {}
    }

    let len = document[start..]
        .find([',', '}', ']'])
        .unwrap_or(document[start..].len());
    (len > 0).then_some(start + len - 1)
}

/// Returns the byte index where the compact object or array starting at `start`
/// ends.
fn compact_container_end(document: &str, start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in document[start..].char_indices() {
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
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }

    None
}

/// Decodes an even-length lowercase-hex string into a fixed `N`-byte array, or
/// `None` when the hex is malformed or decodes to a length other than `N`.
fn decode_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    from_hex(hex)?.try_into().ok()
}

/// Decodes a hex string into bytes — one byte per two hex digits — or `None` on an
/// odd length or a non-hex digit.
fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(hex.get(index..index + 2)?, 16).ok())
        .collect()
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
    /// The document declares no supported signature algorithm — its
    /// `verification.algorithm` member is absent or carries a value the verifier
    /// does not support.
    UnsupportedAlgorithm,
    /// The signature does not verify against the embedded public key over the
    /// document's canonical payload and verification bytes — the document was
    /// altered after signing, its verification metadata was swapped, or its
    /// signature or key is malformed.
    InvalidSignature,
    /// The document embeds no verification public key, so there is nothing to check
    /// the signature against — its `verification.public_key` member is absent.
    /// Rejected as a distinct failure so a stripped key is never mistaken for a
    /// valid export or conflated with a signature mismatch.
    MissingVerificationKey,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                f.write_str("the export declares no supported schema version")
            }
            Self::UnsupportedAlgorithm => {
                f.write_str("the export declares an unsupported signature algorithm")
            }
            Self::InvalidSignature => {
                f.write_str("the signature does not verify the export's payload")
            }
            Self::MissingVerificationKey => {
                f.write_str("the export embeds no verification public key")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// A minimal JSON value the canonical serializer emits.
enum Json {
    /// A JSON string, escaped on output.
    Str(String),
    /// A JSON boolean, emitted verbatim.
    Bool(bool),
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
        ordered_scoped_results(scoped)
            .iter()
            .map(|&(_, result)| result_member(result))
            .collect(),
    )
}

/// Builds the `gaps` section — one record per compliance gap: a framework-scoped
/// result that failed or warned and so requires review. A passing, skipped, or
/// unscoped result is not a gap.
fn gaps_array(
    scoped: &[(Option<&str>, &ControlResult)],
    controls: &[(&str, &str, &str, &str)],
    frameworks: &[(&str, &str, &str)],
) -> Json {
    Json::Array(
        ordered_scoped_results(scoped)
            .iter()
            .filter_map(|&(framework, result)| {
                let framework_id = framework?;
                is_gap(result.status())
                    .then(|| gap_member(result, framework_id, controls, frameworks))
            })
            .collect(),
    )
}

/// Returns framework-scoped results ordered by their stable control and rule ids,
/// then by framework id as a deterministic tie-breaker for scoped records. This
/// is the array ordering the canonical JSON payload relies on.
fn ordered_scoped_results<'a>(
    scoped: &[(Option<&'a str>, &'a ControlResult)],
) -> Vec<(Option<&'a str>, &'a ControlResult)> {
    let mut results = scoped.to_vec();
    results.sort_by(|(framework_a, a), (framework_b, b)| {
        result_id_order(a, b).then_with(|| framework_a.cmp(framework_b))
    });
    results
}

fn result_id_order(a: &ControlResult, b: &ControlResult) -> Ordering {
    a.control_id()
        .cmp(b.control_id())
        .then_with(|| a.rule_id().cmp(b.rule_id()))
}

/// The stable derived id of a control result — `{control_id}:{rule_id}`, composed
/// only from the record's own stable corpus keys, so re-exporting the same corpus
/// yields the same id. Shared by the result and gap records.
fn derived_id(result: &ControlResult) -> String {
    format!("{}:{}", result.control_id(), result.rule_id())
}

/// Builds the JSON record the results section carries — a stable derived id, the
/// control and rule ids it is composed from, and the status label (`PASS`, `FAIL`,
/// `WARNING`, `SKIPPED`, or `ERROR`), the same label the matrix export renders.
/// Gaps use [`gap_member`], which adds the gap-specific reference, severity, and
/// source URL.
fn result_member(result: &ControlResult) -> Json {
    Json::Object(vec![
        ("control_id", Json::Str(result.control_id().to_owned())),
        ("id", Json::Str(derived_id(result))),
        ("rule_id", Json::Str(result.rule_id().to_owned())),
        ("status", Json::Str(result.status().label().to_owned())),
    ])
}

/// Builds a gap record — the control and rule ids, the shared derived id, and the
/// status, plus the gap-specific fields: the catalogued control's own non-CWE
/// framework reference and its severity, and its framework's source URL. The
/// reference and severity are resolved from the control by framework and control
/// id, and the source URL from the framework by id, so each gap shows its own
/// values, never a shared constant or a forced CWE field.
fn gap_member(
    result: &ControlResult,
    framework_id: &str,
    controls: &[(&str, &str, &str, &str)],
    frameworks: &[(&str, &str, &str)],
) -> Json {
    let (severity, reference) = catalogued_control(controls, framework_id, result.control_id());
    let source_url = framework_source_url(frameworks, framework_id);
    Json::Object(vec![
        ("control_id", Json::Str(result.control_id().to_owned())),
        ("id", Json::Str(derived_id(result))),
        ("reference", Json::Str(reference.to_owned())),
        ("rule_id", Json::Str(result.rule_id().to_owned())),
        ("severity", Json::Str(severity.to_owned())),
        ("source_url", Json::Str(source_url.to_owned())),
        ("status", Json::Str(result.status().label().to_owned())),
    ])
}

/// The catalogued control's severity and non-CWE framework reference for a gap on
/// `control_id` under `framework_id`, looked up by framework and control id so each
/// gap shows its own values. An uncatalogued control yields empty strings, never a
/// CWE fallback.
fn catalogued_control<'a>(
    controls: &[(&'a str, &'a str, &'a str, &'a str)],
    framework_id: &str,
    control_id: &str,
) -> (&'a str, &'a str) {
    controls
        .iter()
        .find(|&&(framework, control, _, _)| framework == framework_id && control == control_id)
        .map_or(("", ""), |&(_, _, severity, reference)| {
            (severity, reference)
        })
}

/// The framework's source URL for a gap under `framework_id`, looked up by id so a
/// gap reuses the framework the corpus already holds. An unlisted framework yields
/// an empty source URL.
fn framework_source_url<'a>(
    frameworks: &[(&'a str, &'a str, &'a str)],
    framework_id: &str,
) -> &'a str {
    frameworks
        .iter()
        .find(|&&(id, _, _)| id == framework_id)
        .map_or("", |&(_, _, source_url)| source_url)
}

/// Whether a result of `status` is a compliance gap — a failed or warned outcome
/// the gaps section carries for review.
fn is_gap(status: Status) -> bool {
    matches!(status, Status::Fail | Status::Warning)
}

/// Builds the `scores` section — the MAT-87 control, framework, and environment
/// scores the SDK derived, carried as a traceable, non-authoritative posture
/// summary. Each score value is a percentage string exactly as the score module
/// renders it (half-up one decimal, or "no applicable controls" when undefined);
/// the exporter never recomputes a score or emits an overall verdict.
fn scores_object(environment: &EnvironmentScore) -> Json {
    Json::Object(vec![
        ("control", control_scores(environment)),
        ("environment", Json::Str(environment.ratio().to_string())),
        ("framework", framework_scores(environment)),
        ("incomplete", Json::Bool(environment.incomplete())),
    ])
}

/// Builds the framework-score array — one `{ framework_id, score }` record per
/// framework, ordered by framework id, so each framework score is tied to its
/// framework. The score is the framework's ratio rendered as a percentage string.
fn framework_scores(environment: &EnvironmentScore) -> Json {
    let mut frameworks: Vec<&FrameworkScore> = environment.frameworks().iter().collect();
    frameworks.sort_by(|a, b| a.framework_id().cmp(b.framework_id()));
    Json::Array(
        frameworks
            .iter()
            .map(|&framework| {
                Json::Object(vec![
                    (
                        "framework_id",
                        Json::Str(framework.framework_id().to_owned()),
                    ),
                    ("score", Json::Str(framework.ratio().to_string())),
                ])
            })
            .collect(),
    )
}

/// Builds the control-score array — one `{ control_id, score }` record per scored
/// control across every framework, ordered by control id then rule id. The score is
/// the control's earned-over-applicable ratio rendered as a percentage string.
fn control_scores(environment: &EnvironmentScore) -> Json {
    let mut controls: Vec<&ControlScore> = environment
        .frameworks()
        .iter()
        .flat_map(FrameworkScore::controls)
        .collect();
    controls.sort_by(|a, b| {
        a.control_id()
            .cmp(b.control_id())
            .then_with(|| a.rule_id().cmp(b.rule_id()))
    });
    Json::Array(
        controls
            .iter()
            .map(|&control| {
                Json::Object(vec![
                    ("control_id", Json::Str(control.control_id().to_owned())),
                    ("score", Json::Str(control_ratio(control).to_string())),
                ])
            })
            .collect(),
    )
}

/// The ratio of a single control — its earned points over its applicable weight
/// (its own weight when applicable, zero when not), rendered through the SDK so the
/// exporter never derives the percentage itself. A not-applicable or errored
/// control has no applicable weight, so its ratio is "no applicable controls".
fn control_ratio(control: &ControlScore) -> ScoreRatio {
    let applicable = if control.is_applicable() {
        control.weight()
    } else {
        0
    };
    ScoreRatio::from_weights(control.earned(), applicable)
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
        Json::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
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
