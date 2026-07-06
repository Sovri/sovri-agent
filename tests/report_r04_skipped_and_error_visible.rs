// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-04 - SKIPPED and ERROR results are visible and explained.
//! Covers issue #108.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::evidence::{Evidence, EvidenceKind, EvidenceStore};
use sovri_agent::scanners::ssh;

const RUN_ID: &str = "non-conclusive-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
const CONSENT_HASH: &str =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const DOCKER_HASH: &str = "sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";
const SSH_HASH: &str = "sha256:50ae61e841fac4e8f9e40baf2f53d2128d2c015999fc8d870d1296c0e0e8a9f4";
const CONSENT_CONTROL: &str = "consent.tracker.prior-consent";
const DOCKER_BASE_IMAGE_CONTROL: &str = "container.base-image.supported";
const SSH_ROOT_CONTROL: &str = ssh::PERMIT_ROOT_LOGIN_RULE;
const CONSENT_FAIL_REASON: &str = "non-essential tracker with no consent evidence";
const DOCKER_SKIPPED_REASON: &str = "no Docker daemon is present";
const SSH_ERROR_REASON: &str = "sshd configuration could not be read";

struct NonConclusiveExample {
    control: &'static str,
    status: &'static str,
    reason: &'static str,
}

const NON_CONCLUSIVE_EXAMPLES: [NonConclusiveExample; 2] = [
    NonConclusiveExample {
        control: DOCKER_BASE_IMAGE_CONTROL,
        status: "SKIPPED",
        reason: DOCKER_SKIPPED_REASON,
    },
    NonConclusiveExample {
        control: SSH_ROOT_CONTROL,
        status: "ERROR",
        reason: SSH_ERROR_REASON,
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
            "sovri-agent-mat95-r04-{label}-{}-{unique}",
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

fn evidence(id: &str, control: &str, reason: &str, hash: &str) -> Evidence {
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

fn persisted_non_conclusive_store() -> TempStore {
    let store = TempStore::new("non-conclusive-statuses");
    let records = [
        evidence(
            "ev-consent-fail",
            CONSENT_CONTROL,
            CONSENT_FAIL_REASON,
            CONSENT_HASH,
        ),
        evidence(
            "ev-docker-skipped",
            DOCKER_BASE_IMAGE_CONTROL,
            DOCKER_SKIPPED_REASON,
            DOCKER_HASH,
        ),
        evidence("ev-ssh-error", SSH_ROOT_CONTROL, SSH_ERROR_REASON, SSH_HASH),
    ];
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

fn assert_pdf_text_line(text: &str, expected: &str) {
    let marker = format!("({expected}) Tj\n");
    assert!(
        text.contains(&marker),
        "report contains {expected:?} as a distinct PDF text line; actual PDF text:\n{text}"
    );
}

#[test]
fn non_conclusive_status_appears_with_its_explanation() {
    let store = persisted_non_conclusive_store();
    let output = run_report(RUN_ID, store.path(), EXECUTED_AT);

    assert!(
        output.status.success(),
        "report command exits successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert_pdf_text_line(&text, "Control matrix");
    for example in NON_CONCLUSIVE_EXAMPLES {
        // Then the "Control matrix" section has a row for control "<control>" with status "<status>"
        assert_pdf_text_line(
            &text,
            &format!("Control row: {}: {}", example.control, example.status),
        );
        // And that row shows the explanation "<reason>"
        assert_pdf_text_line(&text, &format!("Explanation: {}", example.reason));
    }
}
