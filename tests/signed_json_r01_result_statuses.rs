// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — every control-result status is carried in the signed export's results
//! array. A corpus holding a single control result of a given status exports a
//! document whose `payload.results` array has an entry with that status, for each
//! of PASS, FAIL, WARNING, SKIPPED, and ERROR. Covers issue #245.

mod signed_json_support;

use signed_json_support::FIXTURE_SIGNING_SEED;
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::Status;

/// The run's fixed executed-at, carried verbatim from the Background.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

/// The five statuses the Scenario Outline's Examples enumerate, each paired with
/// the uppercase label the results array must carry for it.
const EVERY_STATUS: [(Status, &str); 5] = [
    (Status::Pass, "PASS"),
    (Status::Fail, "FAIL"),
    (Status::Warning, "WARNING"),
    (Status::Skipped, "SKIPPED"),
    (Status::Error, "ERROR"),
];

/// Returns the `payload.results` array slice of the compact export — from the `[`
/// after the `"results":` key to its closing `]`. Result records hold no nested
/// array, so the first closing bracket ends it.
fn results_array(document: &str) -> &str {
    let anchor = "\"results\":";
    let start = document
        .find(anchor)
        .expect("the payload carries a results member")
        + anchor.len();
    let rest = &document[start..];
    let end = rest.find(']').expect("the results array is closed") + 1;
    &rest[..end]
}

#[test]
fn every_result_status_is_carried_in_the_results_array() {
    for (status, expected) in EVERY_STATUS {
        // Given a compliance corpus containing a single control result with status "<status>".
        let corpus = Corpus::new(EXECUTED_AT).with_result(status);

        // And a signed JSON export of that corpus.
        let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

        // Then the "payload.results" array has an entry with status "<status>".
        let results = results_array(&document);
        let entry = format!("\"status\":\"{expected}\"");
        assert!(
            results.contains(&entry),
            "the results array carries an entry with status {expected:?} (results: {results})"
        );
    }
}
