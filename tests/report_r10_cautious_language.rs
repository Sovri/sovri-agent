// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-10 - The PDF report uses cautious, non-legal finding language.
//! Covers issue #127.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
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
            "sovri-agent-mat95-r10-{label}-{}-{unique}",
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

fn persisted_consent_store() -> TempStore {
    let store = TempStore::new("cautious-language-corpus");
    let tracker_evidence = Evidence::builder()
        .id("ev-0001")
        .kind(EvidenceKind::RouteBuild)
        .locator("dist/main.js")
        .content_hash(HASH)
        .signal("www.google-analytics.com")
        .build()
        .expect("tracker evidence builds")
        .link_to_control(CONSENT_CONTROL)
        .expect("tracker evidence links");
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&[tracker_evidence])
        .expect("write evidence");
    store
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

fn assert_pdf_text_contains(text: &str, expected: &str) {
    assert!(
        text.contains(expected),
        "report contains {expected:?}; actual PDF text:\n{text}"
    );
}

fn assert_pdf_text_absent(text: &str, forbidden: &str) {
    assert!(
        !text.contains(forbidden),
        "report does not contain {forbidden:?}; actual PDF text:\n{text}"
    );
}

fn section_text<'a>(text: &'a str, section: &str) -> &'a str {
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
    &after_section[..section_end]
}

fn assert_section_contains(section_text: &str, expected: &str) {
    assert!(
        section_text.contains(expected),
        "section contains {expected:?}; actual section text:\n{section_text}"
    );
}

#[test]
fn findings_are_framed_as_potential_gaps_requiring_review() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus with a FAIL result
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the report describes the finding as a "potential gap"
    assert_pdf_text_contains(&text, "potential gap");

    // And the report states the finding "requires review"
    assert_pdf_text_contains(&text, "requires review");

    // And the report describes evidence as "observed", not as proof of illegality
    assert_pdf_text_contains(&text, "observed");
    assert!(
        !text.contains("proof of illegality"),
        "report does not frame evidence as proof of illegality; actual PDF text:\n{text}"
    );
}

#[test]
fn report_contains_no_legal_conclusion_wording() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus with a FAIL result
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the PDF does not contain the text "violation"
    assert_pdf_text_absent(&text, "violation");

    // Then the PDF does not contain the text "illegal"
    assert_pdf_text_absent(&text, "illegal");

    // Then the PDF does not contain the text "unlawful"
    assert_pdf_text_absent(&text, "unlawful");

    // Then the PDF does not contain the text "breach of law"
    assert_pdf_text_absent(&text, "breach of law");
}

#[test]
fn cautious_wording_holds_even_for_a_fail_status() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus with a FAIL result
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let gaps = section_text(&text, "Gaps");

    // Then the gap for control "consent.tracker.prior-consent" has status "FAIL"
    assert_section_contains(&gaps, &format!("Gap: {CONSENT_CONTROL}"));
    assert_section_contains(&gaps, "Status: FAIL");

    // And its reason describes a potential gap requiring review
    assert_section_contains(&gaps, "Reason: potential gap requires review");

    // And its reason asserts no legal violation
    assert_pdf_text_absent(&gaps, "violation");
}
