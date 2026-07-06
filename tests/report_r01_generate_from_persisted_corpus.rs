// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — a PDF report is generated from a persisted MAT-114-style corpus.
//! Covers issue #99.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
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

#[test]
fn generate_a_pdf_report_from_the_persisted_corpus() {
    // Given a persisted evidence store holds the compliance run "shopfront-2026-06-24".
    let store = persisted_consent_store();
    // And the run's fixed executed-at is "2026-06-24T13:16:28Z".
    let output = Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("report")
        .arg("--run")
        .arg(RUN_ID)
        .arg("--evidence-store")
        .arg(store.path())
        .arg("--executed-at")
        .arg(EXECUTED_AT)
        .output()
        .expect("running sovri-agent report");

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
