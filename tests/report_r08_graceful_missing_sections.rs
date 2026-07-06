// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 - Missing optional sections render gracefully.
//! Covers issue #121.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const HASH_ONE: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const HASH_TWO: &str = "sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";
const PASS_CONTROL_ONE: &str = "all-pass.control.one";
const PASS_CONTROL_TWO: &str = "all-pass.control.two";
const SECTION_HEADINGS: [&str; 7] = [
    "Executive summary",
    "Framework coverage",
    "Scores",
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
        let root = loop {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after unix epoch")
                .as_nanos();
            let candidate = std::env::temp_dir().join(format!(
                "sovri-agent-mat95-r08-{label}-{}-{nonce}-{unique}",
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

struct OptionalSectionCase {
    absent: &'static str,
    section: &'static str,
    placeholder: &'static str,
    store: fn() -> TempStore,
}

const OPTIONAL_SECTION_CASES: [OptionalSectionCase; 3] = [
    OptionalSectionCase {
        absent: "no gaps (all controls PASS)",
        section: "Gaps",
        placeholder: "No potential gaps observed",
        store: persisted_all_pass_store,
    },
    OptionalSectionCase {
        absent: "no evidence records",
        section: "Evidence summary",
        placeholder: "No evidence records were collected",
        store: persisted_empty_store,
    },
    OptionalSectionCase {
        absent: "no scores",
        section: "Scores",
        placeholder: "Scores are not available for this run",
        store: persisted_empty_store,
    },
];

fn pass_evidence(id: &str, control: &str, locator: &str, hash: &str) -> Evidence {
    Evidence::builder()
        .id(id)
        .kind(EvidenceKind::RouteBuild)
        .locator(locator)
        .content_hash(hash)
        .signal("PASS")
        .build()
        .expect("passing evidence builds")
        .link_to_control(control)
        .expect("passing evidence links")
}

fn persisted_all_pass_store() -> TempStore {
    let store = TempStore::new("all-pass");
    let records = [
        pass_evidence(
            "ev-pass-001",
            PASS_CONTROL_ONE,
            "dist/pass-one.json",
            HASH_ONE,
        ),
        pass_evidence(
            "ev-pass-002",
            PASS_CONTROL_TWO,
            "dist/pass-two.json",
            HASH_TWO,
        ),
    ];
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store.write_all(&records).expect("write evidence");
    store
}

fn persisted_empty_store() -> TempStore {
    let store = TempStore::new("empty");
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

fn assert_pdf_output(output: &Output, absent: &str) {
    assert!(
        output.status.success(),
        "{absent} report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "{absent} report produces a non-empty PDF"
    );
    assert!(
        output.stdout.starts_with(b"%PDF-"),
        "{absent} report begins with %PDF-"
    );
    assert!(
        output.stdout.ends_with(b"%%EOF\n"),
        "{absent} report ends with %%EOF"
    );
}

fn assert_section_shows_placeholder(text: &str, section: &str, placeholder: &str) {
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
    let placeholder_marker = format!("({placeholder}) Tj\n");
    assert!(
        section_text.contains(&placeholder_marker),
        "section {section:?} contains placeholder {placeholder:?}; actual section text:\n{section_text}"
    );
}

#[test]
fn absent_optional_section_renders_placeholder_not_broken_pdf() {
    for case in OPTIONAL_SECTION_CASES {
        // Given a compliance corpus with <absent>
        let store = (case.store)();

        // When the PDF report is generated
        let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

        // Then a non-empty PDF is produced
        // And the PDF begins with "%PDF-" and ends with "%%EOF"
        assert_pdf_output(&output, case.absent);

        // And the "<section>" section shows the placeholder "<placeholder>"
        let text = String::from_utf8_lossy(&output.stdout);
        assert_section_shows_placeholder(&text, case.section, case.placeholder);
    }
}
