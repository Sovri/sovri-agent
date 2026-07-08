// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-06 — a gap carries its own framework reference and source URL. Each gap in a
//! signed export shows the catalogued control's own non-CWE framework reference,
//! its framework's source URL, and its severity — resolved per gap, not from a
//! shared constant, and never a forced CWE field. Covers issue #266.

mod signed_json_support;

use signed_json_support::{section_value, string_member, FIXTURE_SIGNING_SEED};
use sovri_agent::matrix::Corpus;
use sovri_agent::signed_json;
use sovri_sdk::{ControlResult, Status};

/// The run's fixed executed-at, carried verbatim from the Background.
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

/// One gap example: a control under its framework, catalogued with its own non-CWE
/// reference and severity, and the framework's source URL. The two examples use
/// different frameworks, so the reference and URL are proven per gap, not constant.
struct GapExample {
    framework_id: &'static str,
    version: &'static str,
    source_url: &'static str,
    control: &'static str,
    reference: &'static str,
    severity: &'static str,
    rule: &'static str,
}

/// The two gap examples the Scenario Outline enumerates.
const GAP_EXAMPLES: [GapExample; 2] = [
    GapExample {
        framework_id: "gdpr-eprivacy",
        version: "2016-679",
        source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        control: "consent.tracker.prior-consent",
        reference: "gdpr-eprivacy:2016-679:Art.7",
        severity: "major",
        rule: "consent.detect-trackers-without-consent-evidence",
    },
    GapExample {
        framework_id: "iso-27001",
        version: "2022",
        source_url: "https://www.iso.org/standard/27001",
        control: "host.ssh.permit-root-login",
        reference: "iso-27001:2022:A.8.2",
        severity: "major",
        rule: "host.ssh.detect-permit-root-login",
    },
];

/// Builds a FAIL `ControlResult` for `control`/`rule` at `severity`, which the
/// corpus records as a gap on that control.
fn gap_result(control: &str, rule: &str, severity: &str) -> ControlResult {
    ControlResult::builder()
        .control_id(control)
        .rule_id(rule)
        .status(Status::Fail)
        .severity(severity)
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0")
        .reason("Observed during the compliance run.")
        .build()
        .expect("the gap fixture result validates")
}

#[test]
fn a_gap_carries_its_own_framework_reference_and_source_url() {
    for example in GAP_EXAMPLES {
        // Given a signed JSON export whose gap for control "<control>" carries
        // reference "<reference>", source URL "<url>", severity "<severity>".
        let corpus = Corpus::new(EXECUTED_AT)
            .with_framework(example.framework_id, example.version, example.source_url)
            .with_control(
                example.framework_id,
                example.control,
                "Catalogued control title",
                example.severity,
                8,
                example.reference,
            )
            .with_control_result(
                example.framework_id,
                gap_result(example.control, example.rule, example.severity),
            );
        let document = signed_json::export(&corpus, &FIXTURE_SIGNING_SEED);

        // Then the gap record for that control shows the reference, source URL, and
        // severity, and no reference beginning with "CWE-".
        let gap = section_value(&document, "gaps");
        assert_eq!(
            string_member(gap, "reference").as_deref(),
            Some(example.reference),
            "the gap for {} shows its reference (gap: {gap})",
            example.control
        );
        assert_eq!(
            string_member(gap, "source_url").as_deref(),
            Some(example.source_url),
            "the gap for {} shows its framework source URL (gap: {gap})",
            example.control
        );
        assert_eq!(
            string_member(gap, "severity").as_deref(),
            Some(example.severity),
            "the gap for {} shows its severity (gap: {gap})",
            example.control
        );
        assert!(
            !gap.contains("CWE-"),
            "the gap for {} carries no CWE reference (gap: {gap})",
            example.control
        );
    }
}
