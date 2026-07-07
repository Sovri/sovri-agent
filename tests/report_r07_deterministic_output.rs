// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-07 - Report output is deterministic.
//! Covers issues #117, #118, #119, and #120.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};
use sovri_agent::scanners::ssh;

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const CONSENT_TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
const CONSENT_CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const CONSENT_WARNING_REASON: &str = "consent signal was inconclusive";
const DOCKER_BASE_IMAGE_CONTROL: &str = "container.base-image.supported";
const DOCKER_SKIPPED_REASON: &str = "no Docker daemon is present";
const SSH_ROOT_CONTROL: &str = ssh::PERMIT_ROOT_LOGIN_RULE;
const SSH_ERROR_REASON: &str = "sshd configuration could not be read";
const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const DOCKER_HASH: &str = "sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";
const SSH_HASH: &str = "sha256:50ae61e841fac4e8f9e40baf2f53d2128d2c015999fc8d870d1296c0e0e8a9f4";
const LARGE_CORPUS_RESULTS: usize = 120;

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

fn status_evidence(id: &str, control: &str, reason: &str, hash: &str) -> Evidence {
    Evidence::builder()
        .id(id)
        .kind(EvidenceKind::RouteBuild)
        .locator("control-result.json")
        .content_hash(hash)
        .signal(reason)
        .build()
        .expect("status evidence builds")
        .link_to_control(control)
        .expect("status evidence links")
}

fn consent_warning_evidence() -> Evidence {
    status_evidence(
        "ev-consent-warning",
        CONSENT_CONTROL,
        CONSENT_WARNING_REASON,
        HASH,
    )
}

fn docker_skipped_evidence() -> Evidence {
    status_evidence(
        "ev-docker-skipped",
        DOCKER_BASE_IMAGE_CONTROL,
        DOCKER_SKIPPED_REASON,
        DOCKER_HASH,
    )
}

fn ssh_error_evidence() -> Evidence {
    status_evidence("ev-ssh-error", SSH_ROOT_CONTROL, SSH_ERROR_REASON, SSH_HASH)
}

fn persisted_status_store(label: &str, records: &[Evidence]) -> TempStore {
    let store = TempStore::new(label);
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store.write_all(records).expect("write evidence");
    store
}

fn large_control_evidence(index: usize) -> Evidence {
    Evidence::builder()
        .id(format!("ev-large-{index:03}"))
        .kind(EvidenceKind::RouteBuild)
        .locator(format!("large-corpus/control-{index:03}.json"))
        .content(format!("large corpus control result {index:03}").into_bytes())
        .signal(format!("large corpus signal {index:03}"))
        .build()
        .expect("large corpus evidence builds")
        .link_to_control(format!("large.control.{index:03}"))
        .expect("large corpus evidence links")
}

fn persisted_large_corpus_store() -> TempStore {
    let store = TempStore::new("large-corpus");
    let records: Vec<Evidence> = (0..LARGE_CORPUS_RESULTS)
        .rev()
        .map(large_control_evidence)
        .collect();
    let mut evidence_store = EvidenceStore::open(store.path()).expect("open evidence store");
    evidence_store.write_all(&records).expect("write evidence");
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

fn assert_pdf_lines_ordered(text: &str, expected: &[String]) {
    let mut cursor = 0;
    for line in expected {
        let marker = format!("({line}) Tj\n");
        let remainder = &text[cursor..];
        let offset = remainder.find(&marker).unwrap_or_else(|| {
            panic!("PDF text contains ordered line {line:?}; actual PDF text:\n{text}")
        });
        cursor += offset + marker.len();
    }
}

fn page_start_offsets(pdf: &[u8]) -> Vec<usize> {
    let marker = b"<< /Type /Page /Parent 2 0 R";
    pdf.windows(marker.len())
        .enumerate()
        .filter_map(|(index, window)| (window == marker).then_some(index))
        .collect()
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

#[test]
fn controls_and_rules_render_in_stable_order_regardless_of_input_order() {
    // Given a corpus whose results are supplied in a shuffled order
    let shuffled_records = [
        ssh_error_evidence(),
        consent_warning_evidence(),
        docker_skipped_evidence(),
    ];
    let shuffled_store = persisted_status_store("shuffled-statuses", &shuffled_records);
    let canonical_records = [
        consent_warning_evidence(),
        docker_skipped_evidence(),
        ssh_error_evidence(),
    ];
    let canonical_store = persisted_status_store("canonical-statuses", &canonical_records);

    // When the PDF report is generated
    let shuffled = run_report(RUN_ID, shuffled_store.path(), EXECUTED_AT);
    assert_pdf_output(&shuffled, "shuffled");
    let text = String::from_utf8_lossy(&shuffled.stdout);

    // Then controls are ordered by control id then rule id
    assert_pdf_lines_ordered(
        &text,
        &[
            format!("Control row: {CONSENT_CONTROL}: FAIL"),
            format!("Control row: {DOCKER_BASE_IMAGE_CONTROL}: SKIPPED"),
            format!("Control row: {SSH_ROOT_CONTROL}: ERROR"),
        ],
    );
    assert_pdf_lines_ordered(
        &text,
        &[
            format!("Rule {CONSENT_CMP_RULE}: WARNING"),
            format!("Rule {CONSENT_TRACKER_RULE}: FAIL"),
        ],
    );

    // And the PDF is byte-identical to the report generated from the same results in any other input order
    let canonical = run_report(RUN_ID, canonical_store.path(), EXECUTED_AT);
    assert_pdf_output(&canonical, "canonical");
    assert_eq!(canonical.stdout, shuffled.stdout);
}

#[test]
fn multi_page_report_stays_deterministic_across_regenerations() {
    // Given a large compliance corpus of 120 control results that spans several PDF pages
    let store = persisted_large_corpus_store();

    // And its fixed executed-at is "2026-06-24T13:16:28Z"
    // When the PDF report is generated from the large corpus
    let first = run_report(RUN_ID, store.path(), EXECUTED_AT);
    assert_pdf_output(&first, "first");

    // And the PDF report is generated from the large corpus a second time
    let second = run_report(RUN_ID, store.path(), EXECUTED_AT);
    assert_pdf_output(&second, "second");

    // Then the two PDFs are byte-identical
    assert_eq!(second.stdout, first.stdout);

    // And every page break falls at the same byte offset in both PDFs
    let first_page_offsets = page_start_offsets(&first.stdout);
    let second_page_offsets = page_start_offsets(&second.stdout);
    assert!(
        first_page_offsets.len() > 1,
        "large corpus spans several PDF pages; page starts: {first_page_offsets:?}"
    );
    assert_eq!(second_page_offsets, first_page_offsets);
}
