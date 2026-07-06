// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test: the scan persists collected evidence to a content-addressed
//! store (MAT-94). Records are keyed by their SHA-256 digest, a redacted record
//! reaches the disk without its raw bytes, and re-persisting is idempotent.

mod scan_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use scan_support::{system_debian, user_single_root};
use sovri_agent::scan::persist_evidence;
use sovri_agent::scanners::system::SupportStatus;
use sovri_sdk::{Classification, Evidence, EvidenceStore};

/// A self-cleaning temporary store directory, removed on drop so a test never
/// leaves state under the system temp root.
struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat94-{label}-{}-{unique}",
            std::process::id()
        ));
        TempStore { root }
    }

    /// The store root as the `&str` `persist_evidence` takes.
    fn dir(&self) -> &str {
        self.root.to_str().expect("a UTF-8 temp path")
    }

    /// The store root as a path, for reopening and disk inspection.
    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The evidence the canonical host scanners collect: the system scanner
/// (os-release plus package inventory) and one redacted uid-0 account.
fn collected_evidence() -> Vec<Evidence> {
    let mut evidence = system_debian("9", SupportStatus::EndOfSupport)
        .evidence_log()
        .records()
        .to_vec();
    evidence.extend(user_single_root().evidence_log().records().iter().cloned());
    evidence
}

/// The count of distinct content digests in `evidence` — the store's expected
/// entry count, since the store keys on the digest.
fn distinct_digests(evidence: &[Evidence]) -> usize {
    evidence
        .iter()
        .map(|record| record.content_hash().to_string())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Whether any file under `root` contains `needle` in its raw bytes.
fn any_file_contains(root: &Path, needle: &str) -> bool {
    let mut found = false;
    visit_files(root, &mut |bytes| {
        if contains(bytes, needle.as_bytes()) {
            found = true;
        }
    });
    found
}

fn visit_files(dir: &Path, visit: &mut impl FnMut(&[u8])) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_files(&path, visit);
        } else if let Ok(bytes) = fs::read(&path) {
            visit(&bytes);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Scenario: persisting scanner evidence populates a content-addressed store.
#[test]
fn persisting_scanner_evidence_populates_the_store() {
    let evidence = collected_evidence();
    assert!(!evidence.is_empty(), "the canonical host emits evidence");
    let store = TempStore::new("populates");

    let count = persist_evidence(store.dir(), &evidence).expect("evidence persists");

    // Every distinct record lands, keyed by its digest.
    assert_eq!(count, distinct_digests(&evidence));
    let reopened = EvidenceStore::open(store.path()).expect("reopen the store");
    for record in &evidence {
        assert!(
            reopened.contains_digest(record.content_hash()),
            "the store holds {}",
            record.id()
        );
    }
    // Reading the store back yields the same number of records.
    let read_back = reopened.read_all().expect("read the store back");
    assert_eq!(read_back.records().len(), count);
}

/// Scenario: a redacted account record is stored without its raw bytes.
#[test]
fn a_redacted_record_reaches_the_store_without_its_raw_bytes() {
    let evidence = collected_evidence();
    let redacted = evidence
        .iter()
        .find(|record| {
            record
                .classification()
                .is_some_and(Classification::redacts_raw_value)
        })
        .expect("a redacted account record");
    assert!(
        redacted.excerpt().is_none(),
        "the excerpt is dropped before storage"
    );
    let digest = redacted.content_hash().to_string();
    let store = TempStore::new("redaction");

    persist_evidence(store.dir(), &evidence).expect("evidence persists");

    // The digest is on record...
    let reopened = EvidenceStore::open(store.path()).expect("reopen the store");
    assert!(reopened.contains_digest(&digest));
    // ...its round-tripped record still carries no excerpt...
    let read_back = reopened.read_all().expect("read the store back");
    let stored = read_back
        .records()
        .iter()
        .find(|record| record.content_hash() == digest)
        .expect("the redacted record round-trips");
    assert!(stored.excerpt().is_none());
    // ...and the account's raw home path never reaches the disk.
    assert!(!any_file_contains(store.path(), "/home/root"));
}

/// Scenario: re-persisting the same evidence is idempotent.
#[test]
fn re_persisting_the_same_evidence_is_idempotent() {
    let evidence = collected_evidence();
    let store = TempStore::new("idempotent");

    let first = persist_evidence(store.dir(), &evidence).expect("first persist");
    let second = persist_evidence(store.dir(), &evidence).expect("second persist");

    assert_eq!(first, second, "re-persisting adds no new records");
    assert_eq!(second, distinct_digests(&evidence));
}
