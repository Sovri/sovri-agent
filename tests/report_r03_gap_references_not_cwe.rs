// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 - rendered gaps cite framework/control references, not CWE fallbacks.
//! Covers issue #106.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

struct GapExample {
    control: &'static str,
    reference: &'static str,
    url: &'static str,
    severity: &'static str,
}

const GAP_EXAMPLES: [GapExample; 2] = [
    GapExample {
        control: "consent.tracker.prior-consent",
        reference: "gdpr-eprivacy:2016-679:Art.7",
        url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        severity: "major",
    },
    GapExample {
        control: "host.ssh.permit-root-login",
        reference: "iso-27001:2022:A.8.2",
        url: "https://www.iso.org/standard/27001",
        severity: "major",
    },
];

struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat95-r03-{label}-{}-{unique}",
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

fn persisted_gap_store(control_id: &str) -> TempStore {
    let store = TempStore::new("gap-reference");
    let evidence = Evidence::builder()
        .id("ev-gap-0001")
        .kind(EvidenceKind::RouteBuild)
        .locator("dist/main.js")
        .content_hash(HASH)
        .signal("gap reference fixture")
        .build()
        .expect("gap evidence builds")
        .link_to_control(control_id)
        .expect("gap evidence links");
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&[evidence])
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
fn gap_shows_its_own_framework_control_reference_and_source_url() {
    for example in GAP_EXAMPLES {
        // Given a compliance report whose gap for control "<control>" carries framework reference "<reference>", source URL "<url>", and severity "<severity>"
        let store = persisted_gap_store(example.control);
        let output = run_report("gap-reference-2026-06-24", store.path(), EXECUTED_AT);

        assert!(
            output.status.success(),
            "report command exits successfully, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        // Then the gap for control "<control>" shows control id "<control>"
        assert_pdf_text_line(&text, "Gaps");
        assert_pdf_text_line(&text, &format!("Gap: {}", example.control));
        // And it shows framework reference "<reference>"
        assert_pdf_text_line(
            &text,
            &format!("Framework reference: {}", example.reference),
        );
        // And it shows source URL "<url>"
        assert_pdf_text_line(&text, &format!("Source URL: {}", example.url));
        // And it shows severity "<severity>"
        assert_pdf_text_line(&text, &format!("Severity: {}", example.severity));
        // And it shows no reference beginning with "CWE-"
        assert!(
            !text.contains("CWE-"),
            "report does not contain a CWE fallback reference; actual PDF text:\n{text}"
        );
    }
}
