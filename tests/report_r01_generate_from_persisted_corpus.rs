// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — a PDF report is generated from a persisted MAT-114-style corpus.
//! Covers issues #99 and #100.

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
            "sovri-agent-mat95-{label}-{}-{unique}",
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

fn empty_store(label: &str) -> TempStore {
    let store = TempStore::new(label);
    EvidenceStore::open(store.path()).expect("create empty evidence store");
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

#[test]
fn generate_a_pdf_report_from_the_persisted_corpus() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24".
    let store = persisted_consent_store();
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    // When the maintainer generates the PDF compliance report for "shopfront-2026-06-24".
    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Then a non-empty PDF is produced.
    assert!(!output.stdout.is_empty(), "the PDF has bytes");
    // And the PDF begins with the marker "%PDF-" and ends with the marker "%%EOF".
    assert!(output.stdout.starts_with(b"%PDF-"), "the PDF has a header");
    assert!(
        output.stdout.ends_with(b"%%EOF\n"),
        "the PDF has an EOF marker"
    );
    // And the report's generated date is "2026-06-24T13:16:28Z".
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains(EXECUTED_AT),
        "the fixed generated date is rendered"
    );
}

#[test]
fn report_generation_reads_the_corpus_and_runs_no_scanner() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24".
    let store = persisted_consent_store();
    let before = EvidenceStore::open(store.path())
        .expect("reopen evidence store before report")
        .read_all()
        .expect("read evidence before report");
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    // When the maintainer generates the PDF compliance report for "shopfront-2026-06-24".
    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Then no scanner is executed.
    let after = EvidenceStore::open(store.path())
        .expect("reopen evidence store after report")
        .read_all()
        .expect("read evidence after report");
    assert_eq!(
        after.len(),
        before.len(),
        "report generation does not append scanner evidence"
    );
    // And no network access is performed.
    assert!(
        output.stderr.is_empty(),
        "report generation does not emit host or network acquisition errors"
    );
    // And the report content is derived only from the persisted store.
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("Evidence records: 1"),
        "the persisted evidence record count is rendered"
    );
    let evidence_index = text
        .find("Evidence: ev-0001")
        .expect("the persisted evidence id is rendered");
    let control_index = text
        .find(CONSENT_CONTROL)
        .expect("the persisted control id is rendered");
    let locator_index = text
        .find("dist/main.js")
        .expect("the persisted evidence locator is rendered");
    let signal_index = text
        .find("www.google-analytics.com")
        .expect("the persisted evidence signal is rendered");
    let hash_index = text
        .find(HASH)
        .expect("the persisted evidence integrity hash is rendered");
    assert!(
        evidence_index < control_index
            && control_index < locator_index
            && locator_index < signal_index
            && signal_index < hash_index,
        "the evidence record is rendered before its indented fields"
    );
}

#[test]
fn reject_invalid_report_inputs_without_pdf_output() {
    let store = persisted_consent_store();

    let invalid_run = run_report("shopfront/2026-06-24", store.path(), EXECUTED_AT);
    assert!(!invalid_run.status.success(), "invalid run id is rejected");
    assert!(
        String::from_utf8_lossy(&invalid_run.stderr).contains("invalid --run id"),
        "invalid run id explains the validation error"
    );
    assert!(
        invalid_run.stdout.is_empty(),
        "no PDF is written on usage error"
    );

    let invalid_timestamp = run_report(RUN_ID, store.path(), "2026-06-24 13:16:28");
    assert!(
        !invalid_timestamp.status.success(),
        "malformed execution timestamp is rejected"
    );
    assert!(
        String::from_utf8_lossy(&invalid_timestamp.stderr).contains("invalid --executed-at"),
        "invalid timestamp explains the validation error"
    );
    assert!(
        invalid_timestamp.stdout.is_empty(),
        "no PDF is written on timestamp error"
    );

    let missing_store = TempStore::new("missing-corpus");
    let missing_store_output = run_report(RUN_ID, missing_store.path(), EXECUTED_AT);
    assert!(
        !missing_store_output.status.success(),
        "missing evidence store is rejected"
    );
    assert!(
        String::from_utf8_lossy(&missing_store_output.stderr)
            .contains("invalid --evidence-store path"),
        "missing evidence store explains the validation error"
    );
    assert!(
        missing_store_output.stdout.is_empty(),
        "no PDF is written for a missing store"
    );
}

#[test]
fn accept_maximum_length_run_ids_and_empty_evidence_stores() {
    let store = empty_store("empty-corpus");
    let run_id = "a".repeat(128);
    let output = run_report(&run_id, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "maximum length run id and empty evidence store are accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains(&format!("Run: {run_id}")),
        "maximum length run id is rendered"
    );
    assert!(
        text.contains("Evidence records: 0"),
        "empty evidence store count is rendered"
    );
}
