// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-08 - the canonical payload orders object keys and records deterministically.
//! A signed export of the fixed "shopfront-2026-06-24" consent corpus emits every
//! payload object with lexicographically ordered keys, and orders `payload.results`
//! by control id then rule id. Covers issue #274.

mod signed_json_support;

use serde_json::Value;
use signed_json_support::{
    assert_object_keys_are_lexicographic, consent_corpus, section_value, FIXTURE_SIGNING_SEED,
};
use sovri_agent::signed_json;

const CONTROL: &str = "consent.tracker.prior-consent";
const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";
const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";

#[test]
fn the_canonical_payload_orders_object_keys_and_records_deterministically() {
    // Given the "shopfront-2026-06-24" consent corpus with fixed executed-at.
    let corpus = consent_corpus();

    // When the signed JSON is exported from the corpus.
    let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);
    let payload = section_value(&document, "payload");

    // Then every JSON object in the payload has its keys in lexicographic order.
    assert_object_keys_are_lexicographic(payload);

    // And "payload.results" entries are ordered by control id then rule id.
    let result_keys = result_sort_keys(section_value(payload, "results"));
    assert_eq!(
        result_keys,
        vec![
            (CONTROL.to_owned(), CMP_RULE.to_owned()),
            (CONTROL.to_owned(), TRACKER_RULE.to_owned()),
        ],
        "payload.results entries are ordered by control id then rule id"
    );
}

fn result_sort_keys(results: &str) -> Vec<(String, String)> {
    let values: Vec<Value> =
        serde_json::from_str(results).expect("payload.results is a JSON array");
    values
        .iter()
        .map(|value| {
            let control_id = value
                .get("control_id")
                .and_then(Value::as_str)
                .expect("a result record carries control_id");
            let rule_id = value
                .get("rule_id")
                .and_then(Value::as_str)
                .expect("a result record carries rule_id");
            (control_id.to_owned(), rule_id.to_owned())
        })
        .collect()
}
