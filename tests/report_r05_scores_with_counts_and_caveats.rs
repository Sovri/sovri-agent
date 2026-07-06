// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-05 - Scores render with counts and caveats, not as legal risk ratings.
//! Covers issues #111 and #112.

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

fn assert_pdf_text_line(text: &str, expected: &str) {
    let marker = format!("({expected}) Tj\n");
    assert!(
        text.contains(&marker),
        "report contains {expected:?} as a distinct PDF text line; actual PDF text:\n{text}"
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
    assert_pdf_text_line(&text, "Scores are not a legal risk rating.");
}
