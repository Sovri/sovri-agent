// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 - Evidence integrity metadata renders in the appendix.
//! Covers issue #124.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const EVIDENCE_ID: &str = "ev-0001";
const CARRIED_EVIDENCE_ID: &str = "ev-0002";
const MISSING_INTEGRITY_EVIDENCE_ID: &str = "ev-0003";
const LOCATOR: &str = "dist/main.js";
const EVIDENCE_FIELD_INDENT: &str = "  ";
const DIGEST: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const CARRIED_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MISSING_INTEGRITY_LIMITATION: &str = "integrity metadata not available";
const SECTION_HEADINGS: [&str; 8] = [
    "Executive summary",
    "Framework coverage",
    "Scores",
    "Control matrix",
    "Gaps",
    "Evidence summary",
    "Evidence appendix",
    "Remediation",
];

struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat95-r09-{label}-{}-{unique}",
            std::process::id()
        ));
        TempStore { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn persisted_integrity_store() -> TempStore {
    let store = TempStore::new("integrity-corpus");
    let evidence = Evidence::builder()
        .id(EVIDENCE_ID)
        .kind(EvidenceKind::RouteBuild)
        .locator(LOCATOR)
        .content_hash(DIGEST)
        .signal("www.google-analytics.com")
        .build()
        .expect("integrity evidence builds")
        .link_to_control(CONSENT_CONTROL)
        .expect("integrity evidence links");
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&[evidence])
        .expect("write evidence");
    store
}

fn persisted_store_with_changed_blob() -> TempStore {
    let store = TempStore::new("carried-integrity-corpus");
    let evidence = Evidence::builder()
        .id(CARRIED_EVIDENCE_ID)
        .kind(EvidenceKind::RouteBuild)
        .locator(LOCATOR)
        .content(Vec::new())
        .content_hash(CARRIED_DIGEST)
        .signal("www.google-analytics.com")
        .build()
        .expect("carried integrity evidence builds")
        .link_to_control(CONSENT_CONTROL)
        .expect("carried integrity evidence links");
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&[evidence])
        .expect("write evidence");
    overwrite_only_blob(store.path(), b"abc");
    store
}

fn persisted_store_without_integrity_metadata() -> TempStore {
    let store = TempStore::new("missing-integrity-corpus");
    let shard = store.path().join("objects").join("00");
    fs::create_dir_all(&shard).expect("create evidence object shard");
    fs::write(
        shard.join("missing-integrity.rec"),
        [
            "format\tevidence-record-v1",
            "id\tev-0003",
            "kind\troute-build",
            "locator\tdist/main.js",
            "signal\twww.google-analytics.com",
            "control-id\tconsent.tracker.prior-consent",
            "control\tconsent.tracker.prior-consent",
            "",
        ]
        .join("\n"),
    )
    .expect("write legacy evidence record without integrity metadata");
    store
}

fn overwrite_only_blob(root: &Path, bytes: &[u8]) {
    let mut blobs = Vec::new();
    collect_blob_paths(root, &mut blobs);
    assert_eq!(blobs.len(), 1, "expected one stored content blob");
    fs::write(&blobs[0], bytes).expect("change stored blob");
}

fn collect_blob_paths(dir: &Path, blobs: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read evidence store directory") {
        let path = entry.expect("read evidence store entry").path();
        if path.is_dir() {
            collect_blob_paths(&path, blobs);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("blob") {
            blobs.push(path);
        }
    }
}

fn run_report(run_id: &str, store: &Path, executed_at: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("report")
        .arg("--run")
        .arg(run_id)
        .arg("--evidence-store")
        .arg(store)
        .arg("--executed-at")
        .arg(executed_at)
        .output()
        .expect("running sovri-agent report")
}

fn assert_section_shows_line(text: &str, section: &str, expected: &str) {
    let section_marker = format!("({section}) Tj\n");
    let section_start = text
        .find(&section_marker)
        .unwrap_or_else(|| panic!("report contains section {section:?}; actual PDF text:\n{text}"));
    let after_section = &text[section_start + section_marker.len()..];
    let section_end = SECTION_HEADINGS
        .iter()
        .filter(|heading| **heading != section)
        .filter_map(|heading| after_section.find(&format!("({heading}) Tj\n")))
        .min()
        .unwrap_or(after_section.len());
    let section_text = &after_section[..section_end];
    let expected_marker = format!("({expected}) Tj\n");
    assert!(
        section_text.contains(&expected_marker),
        "section {section:?} contains line {expected:?}; actual section text:\n{section_text}"
    );
}

#[test]
fn appendix_shows_algorithm_and_digest_for_stored_record() {
    // Given a persisted evidence store holds a record for control "consent.tracker.prior-consent":
    //   | evidence_id | locator      | integrity                                                               |
    //   | ev-0001     | dist/main.js | sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad |
    let store = persisted_integrity_store();

    // And a compliance report generated from that store
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the "Evidence appendix" section shows evidence id "ev-0001"
    assert_section_shows_line(&text, "Evidence appendix", "Evidence: ev-0001");

    // And it shows the location "dist/main.js"
    assert_section_shows_line(&text, "Evidence appendix", "  Location: dist/main.js");

    // And it shows the integrity algorithm "SHA-256"
    assert_section_shows_line(&text, "Evidence appendix", "  Integrity algorithm: SHA-256");

    // And it shows the digest "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert_section_shows_line(&text, "Evidence appendix", &format!("  Digest: {DIGEST}"));
}

#[test]
fn appendix_reads_integrity_metadata_from_the_store_without_recomputing_it() {
    // Given a persisted evidence store holds a record "ev-0002" with integrity "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    let store = persisted_store_with_changed_blob();

    // And a compliance report generated from that store
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    // And no scanner or hasher is executed while generating the report
    assert!(
        output.status.success(),
        "report command exits successfully without recomputing evidence bytes, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the "Evidence appendix" shows the digest "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert_section_shows_line(
        &text,
        "Evidence appendix",
        &format!("  Digest: {CARRIED_DIGEST}"),
    );
}

#[test]
fn appendix_notes_a_collection_limitation_when_integrity_metadata_is_absent() {
    // Given a persisted evidence store holds a record "ev-0003" with no integrity metadata
    let store = persisted_store_without_integrity_metadata();

    // And a compliance report generated from that store
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully for missing integrity metadata, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the "Evidence appendix" section shows evidence id "ev-0003"
    assert_section_shows_line(
        &text,
        "Evidence appendix",
        &format!("Evidence: {MISSING_INTEGRITY_EVIDENCE_ID}"),
    );

    // And it notes the limitation "integrity metadata not available"
    assert_section_shows_line(
        &text,
        "Evidence appendix",
        &format!("{EVIDENCE_FIELD_INDENT}Limitation: {MISSING_INTEGRITY_LIMITATION}"),
    );
}
