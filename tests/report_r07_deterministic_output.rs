// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 - Report output is deterministic.
//! Covers issues #117 and #118.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
        let root = loop {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after unix epoch")
                .as_nanos();
            let candidate = std::env::temp_dir().join(format!(
                "sovri-agent-mat95-r07-{label}-{}-{nonce}-{unique}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    let path = candidate.display();
                    panic!("create temporary evidence store directory {path}: {error}");
                }
            }
        };
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
    let store = TempStore::new("consent-corpus");
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

fn assert_pdf_output(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.starts_with(b"%PDF-"),
        "{label} has a PDF header"
    );
    assert!(
        output.stdout.ends_with(b"%%EOF\n"),
        "{label} has a PDF EOF marker"
    );
}

fn assert_no_pdf_creation_timestamp(pdf: &[u8]) {
    let text = String::from_utf8_lossy(pdf);
    for forbidden in ["/CreationDate", "/ModDate", "D:"] {
        assert!(
            !text.contains(forbidden),
            "PDF embeds creation timestamp marker {forbidden:?}; actual PDF bytes:\n{text}"
        );
    }
}

#[test]
fn generating_the_report_twice_yields_byte_identical_pdfs() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z"
    let store = persisted_consent_store();

    // When the PDF report is generated from the corpus
    let first = run_report(RUN_ID, store.path(), EXECUTED_AT);
    assert_pdf_output(&first, "first");

    // And the PDF report is generated from the same corpus a second time
    let second = run_report(RUN_ID, store.path(), EXECUTED_AT);
    assert_pdf_output(&second, "second");

    // Then the two PDFs are byte-identical
    assert_eq!(second.stdout, first.stdout);
}

#[test]
fn generated_date_is_the_runs_fixed_executed_at_not_the_wall_clock() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at "2026-06-24T13:16:28Z"
    let store = persisted_consent_store();

    // When the PDF report is generated from the corpus
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);
    assert_pdf_output(&output, "report");
    let text = String::from_utf8_lossy(&output.stdout);

    // Then the report's generated date is "2026-06-24T13:16:28Z"
    assert!(
        text.contains(&format!("Generated date: {EXECUTED_AT}")),
        "PDF renders fixed generated date {EXECUTED_AT:?}; actual PDF bytes:\n{text}"
    );

    // And the PDF embeds no wall-clock creation timestamp
    assert_no_pdf_creation_timestamp(&output.stdout);
}
