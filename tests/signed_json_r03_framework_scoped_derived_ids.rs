// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-03 regression — derived result and gap ids preserve framework scope when
//! the same control and rule are evaluated under more than one framework.

mod signed_json_support;

use serde_json::Value;
use signed_json_support::{
    json_string_member, CONTROL, CONTROL_REFERENCE, CONTROL_SEVERITY, CONTROL_TITLE,
    CONTROL_WEIGHT, EVIDENCE_ID, EXECUTED_AT, FIXTURE_SIGNING_SEED, FRAMEWORK, FRAMEWORK_URL,
    FRAMEWORK_VERSION, RUN_ID, TRACKER_RULE,
};
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

const SECOND_FRAMEWORK: &str = "iso-27001";
const SECOND_FRAMEWORK_VERSION: &str = "2022";
const SECOND_FRAMEWORK_URL: &str = "https://www.iso.org/standard/27001";
const SECOND_CONTROL_REFERENCE: &str = "iso-27001:2022:A.5.34";

fn failing_result() -> ControlResult {
    ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(TRACKER_RULE)
        .status(Status::Fail)
        .severity(CONTROL_SEVERITY)
        .weight(CONTROL_WEIGHT)
        .evidence_refs([EVIDENCE_ID])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0")
        .reason("Non-essential tracker loaded without recorded consent.")
        .build()
        .expect("the scoped result fixture validates")
}

fn multi_framework_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_framework(
            SECOND_FRAMEWORK,
            SECOND_FRAMEWORK_VERSION,
            SECOND_FRAMEWORK_URL,
        )
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            CONTROL_SEVERITY,
            CONTROL_WEIGHT,
            CONTROL_REFERENCE,
        )
        .with_control(
            SECOND_FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            CONTROL_SEVERITY,
            CONTROL_WEIGHT,
            SECOND_CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, failing_result())
        .with_control_result(SECOND_FRAMEWORK, failing_result())
        .with_evidence(EVIDENCE_ID, "dist/main.js")
}

fn payload_records<'a>(export: &'a Value, section: &str) -> &'a [Value] {
    export
        .get("payload")
        .and_then(|payload| payload.get(section))
        .and_then(Value::as_array)
        .map_or_else(
            || panic!("the signed export carries payload.{section} records"),
            Vec::as_slice,
        )
}

fn assert_framework_scoped_ids(records: &[Value], section: &str) {
    assert_eq!(
        records.len(),
        2,
        "the {section} section carries one record per framework"
    );

    for framework_id in [FRAMEWORK, SECOND_FRAMEWORK] {
        let record = records
            .iter()
            .find(|record| json_string_member(record, "framework_id") == Some(framework_id))
            .unwrap_or_else(|| panic!("{section} carries a record for framework {framework_id}"));
        let expected_id = format!("{framework_id}:{CONTROL}:{TRACKER_RULE}");
        assert_eq!(
            json_string_member(record, "id"),
            Some(expected_id.as_str()),
            "{section} record ids include framework scope (record: {record})"
        );
        assert_eq!(
            json_string_member(record, "control_id"),
            Some(CONTROL),
            "{section} record keeps the control id (record: {record})"
        );
        assert_eq!(
            json_string_member(record, "rule_id"),
            Some(TRACKER_RULE),
            "{section} record keeps the rule id (record: {record})"
        );
    }
}

#[test]
fn framework_scope_disambiguates_result_and_gap_record_ids() {
    let document = signed_json::export(&multi_framework_corpus(), &FIXTURE_SIGNING_SEED);
    let export: Value = serde_json::from_str(&document).expect("the signed export parses as JSON");

    assert_framework_scoped_ids(payload_records(&export, "results"), "results");
    assert_framework_scoped_ids(payload_records(&export, "gaps"), "gaps");
}
