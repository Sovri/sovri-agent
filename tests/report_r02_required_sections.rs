// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-02 - the PDF report contains every required section.
//! Covers issues #101, #102, #103, #104, and #105.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const WARNING_RUN_ID: &str = "shopfront-warning-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const SCAN_TARGET: &str = "shopfront";
const FRAMEWORK_ID: &str = "gdpr-eprivacy";
const CATALOG_VERSION: &str = "2016-679";
const RESULT_COUNTS: &str = "1 FAIL, 1 PASS";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const WARNING_REASON: &str = "consent signal was inconclusive";
const CONSENT_REMEDIATION: &str = "Block non-essential trackers until the visitor records consent.";
const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const REQUIRED_SECTIONS: [&str; 6] = [
    "Executive summary",
    "Framework coverage",
    "Control matrix",
    "Gaps",
    "Evidence summary",
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
            "sovri-agent-mat95-r02-{label}-{}-{unique}",
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
    let store = TempStore::new("persisted-corpus");
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

fn warning_consent_store() -> TempStore {
    let store = TempStore::new("warning-corpus");
    let warning_evidence = Evidence::builder()
        .id("ev-warning-0001")
        .kind(EvidenceKind::RouteBuild)
        .locator("dist/main.js")
        .content_hash(HASH)
        .signal(WARNING_REASON)
        .build()
        .expect("warning evidence builds")
        .link_to_control(CONSENT_CONTROL)
        .expect("warning evidence links");
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&[warning_evidence])
        .expect("write warning evidence");
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

fn assert_pdf_text_line(text: &str, expected: &str) {
    let marker = format!("({expected}) Tj\n");
    assert!(
        text.contains(&marker),
        "report contains {expected:?} as a distinct PDF text line; actual PDF text:\n{text}"
    );
}

#[test]
fn each_required_section_is_present_in_the_report() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for section in REQUIRED_SECTIONS {
        // Then the report contains the "<section>" section
        assert_pdf_text_line(&text, section);
    }
}

#[test]
fn executive_summary_carries_the_runs_headline_facts() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the "Executive summary" section lists framework "gdpr-eprivacy" as covered
    assert_pdf_text_line(&text, "Executive summary");
    assert_pdf_text_line(&text, &format!("Framework covered: {FRAMEWORK_ID}"));
    // And it shows the scan target "shopfront"
    assert_pdf_text_line(&text, &format!("Scan target: {SCAN_TARGET}"));
    // And it shows the generated date "2026-06-24T13:16:28Z"
    assert_pdf_text_line(&text, &format!("Generated date: {EXECUTED_AT}"));
    // And it shows the catalog version "2016-679"
    assert_pdf_text_line(&text, &format!("Catalog version: {CATALOG_VERSION}"));
    // And it shows the result counts "1 FAIL, 1 PASS"
    assert_pdf_text_line(&text, &format!("Result counts: {RESULT_COUNTS}"));
}

#[test]
fn control_matrix_lists_the_control_with_a_status_per_rule() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the "Control matrix" section has a row for control "consent.tracker.prior-consent"
    assert_pdf_text_line(&text, "Control matrix");
    assert_pdf_text_line(&text, &format!("Control: {CONSENT_CONTROL}"));
    // And that control shows status "FAIL" for rule "consent.detect-trackers-without-consent-evidence"
    assert_pdf_text_line(&text, &format!("Rule {TRACKER_RULE}: FAIL"));
    // And that control shows status "PASS" for rule "consent.detect-cmp-misconfiguration"
    assert_pdf_text_line(&text, &format!("Rule {CMP_RULE}: PASS"));
}

#[test]
fn control_matrix_renders_a_warning_result_visibly() {
    // Given a compliance report generated from a run whose control "consent.tracker.prior-consent" has a WARNING result from rule "consent.detect-cmp-misconfiguration" with reason "consent signal was inconclusive"
    let store = warning_consent_store();
    let output = run_report(WARNING_RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the "Control matrix" section has a row for control "consent.tracker.prior-consent" with status "WARNING" for rule "consent.detect-cmp-misconfiguration"
    assert_pdf_text_line(&text, "Control matrix");
    assert_pdf_text_line(&text, &format!("Control: {CONSENT_CONTROL}"));
    assert_pdf_text_line(&text, &format!("Rule {CMP_RULE}: WARNING"));
    // And that row shows the explanation "consent signal was inconclusive"
    assert_pdf_text_line(&text, &format!("Explanation: {WARNING_REASON}"));
}

#[test]
fn gap_section_carries_remediation_guidance() {
    // Given a compliance report generated from the "shopfront-2026-06-24" consent corpus
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the "Gaps" section for control "consent.tracker.prior-consent" includes remediation "Block non-essential trackers until the visitor records consent."
    assert_pdf_text_line(&text, "Gaps");
    assert_pdf_text_line(
        &text,
        &format!("Remediation for {CONSENT_CONTROL}: {CONSENT_REMEDIATION}"),
    );
}
