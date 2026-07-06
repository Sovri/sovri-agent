// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 - Scores render with counts and caveats, not as legal risk ratings.
//! Covers issues #111, #112, #113, and #114.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat95-r05-{label}-{}-{unique}",
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

fn run_report_with_framework_score(
    run_id: &str,
    store: &Path,
    executed_at: &str,
    framework_score: &str,
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("report")
        .arg("--run")
        .arg(run_id)
        .arg("--evidence-store")
        .arg(store)
        .arg("--executed-at")
        .arg(executed_at)
        .arg("--framework-score")
        .arg(framework_score)
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

fn pdf_text_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|line| line.strip_prefix('(')?.strip_suffix(") Tj"))
}

fn assert_no_score_label(text: &str, forbidden_label: &str) {
    let forbidden_label = forbidden_label.to_ascii_lowercase();
    let offending_line = pdf_text_lines(text).find(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("score") && line.contains(&forbidden_label)
    });
    assert!(
        offending_line.is_none(),
        "no score in the report is labelled {forbidden_label:?}; offending line: {offending_line:?}; actual PDF text:\n{text}"
    );
}

#[test]
fn scores_render_with_their_scope_value_and_result_counts() {
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the report shows framework score "gdpr-eprivacy" as "0.0%"
    assert_pdf_text_line(&text, "Framework score gdpr-eprivacy: 0.0%");
    // And it shows the result counts "1 FAIL, 1 PASS, 0 WARNING, 0 SKIPPED, 0 ERROR"
    assert_pdf_text_line(
        &text,
        "Result counts: 1 FAIL, 1 PASS, 0 WARNING, 0 SKIPPED, 0 ERROR",
    );
}

#[test]
fn scores_carry_a_posture_caveat() {
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the score section states that scores summarize observed compliance posture
    assert_pdf_text_line(&text, "Scores summarize observed compliance posture.");
    // And it states that scores are not a legal risk rating
    assert_pdf_text_line(&text, "Scores do not provide legal-risk ratings.");
}

#[test]
fn scores_are_never_labelled_as_a_legal_or_risk_rating() {
    let store = persisted_consent_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then no score in the report is labelled "legal risk rating"
    assert_no_score_label(&text, "legal risk rating");
    // And no score in the report is labelled "risk score"
    assert_no_score_label(&text, "risk score");
}

#[test]
fn score_percentages_render_at_the_boundaries_with_caveats() {
    for framework_score in ["0.0%", "100.0%"] {
        let store = persisted_consent_store();
        // Given the run's MAT-87 framework score is provided as "<score>"
        // When the report is generated
        let output =
            run_report_with_framework_score(RUN_ID, store.path(), EXECUTED_AT, framework_score);

        assert!(
            output.status.success(),
            "report command exits successfully for score {framework_score}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        // Then the report shows framework score "gdpr-eprivacy" as "<score>"
        assert_pdf_text_line(
            &text,
            &format!("Framework score gdpr-eprivacy: {framework_score}"),
        );
        // And the score section states that scores are not a legal risk rating
        assert_pdf_text_line(&text, "Scores do not provide legal-risk ratings.");
    }
}
