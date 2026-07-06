// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 - Sensitive evidence is redacted or summarized, never leaked.
//! Covers issue #115.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Classification, Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

struct TestEvidence {
    id: &'static str,
    report_kind: &'static str,
    locator: &'static str,
    classification: Classification,
    raw_value: &'static str,
    integrity: &'static str,
    key: Option<&'static str>,
}

impl TestEvidence {
    fn to_evidence(&self) -> Evidence {
        let mut builder = Evidence::builder()
            .id(self.id)
            .kind(EvidenceKind::Config)
            .locator(self.locator)
            .classification(self.classification)
            .content_hash(self.integrity)
            .excerpt(self.raw_value);
        if let Some(key) = self.key {
            builder = builder.key(key);
        }
        builder.build().expect("classified evidence builds")
    }
}

const CLASSIFIED_EVIDENCE: &[TestEvidence] = &[
    TestEvidence {
        id: "ev-secret-env",
        report_kind: "config",
        locator: ".env.example:3",
        classification: Classification::Secret,
        raw_value: "sk_live_EXAMPLEonly_NOT_A_REAL_KEY",
        integrity: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        key: None,
    },
    TestEvidence {
        id: "ev-sensitive-account",
        report_kind: "account",
        locator: "config/users.yaml:12",
        classification: Classification::Sensitive,
        raw_value: "admin@shopfront.example",
        integrity: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        key: Some("account"),
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
            "sovri-agent-mat95-r06-{label}-{}-{unique}",
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

fn classified_evidence_store() -> TempStore {
    let store = TempStore::new("classified-corpus");
    let evidence = CLASSIFIED_EVIDENCE
        .iter()
        .map(TestEvidence::to_evidence)
        .collect::<Vec<_>>();
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store
        .write_all(&evidence)
        .expect("write classified evidence");
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

fn pdf_text_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.strip_prefix('(')?.strip_suffix(") Tj"))
        .collect()
}

fn assert_record_metadata(text: &str, kind: &str, locator: &str, integrity: &str) {
    let lines = pdf_text_lines(text);
    let section_index = lines
        .iter()
        .position(|line| *line == "Evidence summary")
        .unwrap_or_else(|| panic!("report contains the Evidence summary section:\n{text}"));
    let locator_line = format!("  Locator: {locator}");
    let locator_index = match lines[section_index..]
        .iter()
        .position(|line| *line == locator_line)
    {
        Some(offset) => section_index + offset,
        None => panic!("report contains locator {locator:?}; actual PDF text:\n{text}"),
    };
    let record_start = lines[..locator_index]
        .iter()
        .rposition(|line| line.starts_with("Evidence: "))
        .expect("locator belongs to an evidence record");
    let record_end = lines[locator_index..]
        .iter()
        .position(|line| line.starts_with("Evidence: "))
        .map_or(lines.len(), |offset| locator_index + offset);
    let record_lines = &lines[record_start..record_end];

    for expected in [
        format!("  Kind: {kind}"),
        locator_line,
        format!("  Integrity: {integrity}"),
        "  Redacted: yes".to_string(),
    ] {
        assert!(
            record_lines.iter().any(|line| **line == expected),
            "record {locator:?} contains {expected:?}; actual record lines: {record_lines:?}"
        );
    }
}

#[test]
fn a_classified_record_is_summarized_to_its_metadata() {
    // Given a persisted evidence store holds these classified evidence records:
    //   | kind    | locator              | classification | raw_value                          | integrity                                                               |
    //   | config  | .env.example:3       | Secret         | sk_live_EXAMPLEonly_NOT_A_REAL_KEY | sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad |
    //   | account | config/users.yaml:12 | Sensitive      | admin@shopfront.example            | sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
    // And a compliance report generated from that store
    let store = classified_evidence_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    // Then the "Evidence summary" section shows the record kind "<kind>"
    // And it shows the locator "<locator>"
    // And it shows the integrity "<integrity>"
    // And it marks the "<locator>" record as redacted
    for example in CLASSIFIED_EVIDENCE {
        assert_record_metadata(
            &text,
            example.report_kind,
            example.locator,
            example.integrity,
        );
    }
}
