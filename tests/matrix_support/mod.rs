// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for the MAT-96 matrix acceptance tests.
//!
//! Query an exported `SpreadsheetML` workbook by worksheet name and read the
//! cell values of its rows, so each acceptance test asserts against the sheet it
//! cares about without re-parsing the XML by hand.

#![allow(dead_code)]

/// Returns the `<Worksheet>` … `</Worksheet>` slice whose `ss:Name` is `name`.
///
/// # Panics
/// Panics if no worksheet with that name is present, so a test that names a
/// missing sheet fails with a clear message.
#[must_use]
pub fn worksheet<'a>(xml: &'a str, name: &str) -> &'a str {
    let needle = format!("ss:Name=\"{name}\"");
    let mut rest = xml;
    loop {
        let at = rest
            .find("<Worksheet")
            .unwrap_or_else(|| panic!("the workbook has a worksheet named {name:?}"));
        let after = &rest[at..];
        let tag_end = after
            .find('>')
            .expect("the worksheet opening tag is closed");
        if after[..tag_end].contains(&needle) {
            let end =
                after.find("</Worksheet>").expect("the worksheet is closed") + "</Worksheet>".len();
            return &after[..end];
        }
        rest = &after[tag_end..];
    }
}

/// Returns the cell values of every `<Row>` in `fragment`, one inner `Vec` per
/// row, reading the text of each `<Data>` cell in order.
#[must_use]
pub fn rows(fragment: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = fragment;
    while let Some(at) = rest.find("<Row") {
        let after = &rest[at..];
        let end = after
            .find("</Row>")
            .map_or(after.len(), |e| e + "</Row>".len());
        out.push(cell_values(&after[..end]));
        rest = &after[end..];
    }
    out
}

/// Reads the text of every `<Data>` cell in a single `<Row>` fragment.
#[must_use]
pub fn cell_values(row: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = row;
    while let Some(at) = rest.find("<Data") {
        let after = &rest[at..];
        let Some(open_end) = after.find('>') else {
            break;
        };
        let inner = &after[open_end + 1..];
        let Some(close) = inner.find("</Data>") else {
            break;
        };
        values.push(inner[..close].to_string());
        rest = &inner[close + "</Data>".len()..];
    }
    values
}

/// Returns the first row whose cells contain `value`, if any.
#[must_use]
pub fn row_containing<'a>(rows: &'a [Vec<String>], value: &str) -> Option<&'a Vec<String>> {
    rows.iter().find(|cells| cells.iter().any(|c| c == value))
}

use sovri_agent::matrix::{Classification, Corpus};
use sovri_sdk::{ControlResult, Status};

/// The fixed executed-at the consent corpus records, reused as the generated date.
pub const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";
/// The framework the consent corpus covers.
pub const FRAMEWORK: &str = "gdpr-eprivacy";
/// The consent framework's catalog version.
pub const FRAMEWORK_VERSION: &str = "2016-679";
/// The consent framework's source URL.
pub const FRAMEWORK_URL: &str = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
/// The single control both consent results evaluate.
pub const CONTROL: &str = "consent.tracker.prior-consent";
/// The catalogued title of that control, as read from the persisted catalog.
pub const CONTROL_TITLE: &str = "Prior consent for tracker access";
/// The non-CWE framework reference the consent control maps to, rendered verbatim
/// on its Gaps row.
pub const CONTROL_REFERENCE: &str = "gdpr-eprivacy:2016-679:Art.7";
/// The rule that fails: a non-essential tracker with no consent evidence.
pub const TRACKER_RULE: &str = "consent.detect-trackers-without-consent-evidence";
/// The rule that passes: the consent-management platform is configured.
pub const CMP_RULE: &str = "consent.detect-cmp-misconfiguration";

/// The SSH root-login control the reference corpus adds as a second gap, under a
/// second framework, so the Gaps sheet renders two distinct framework references.
pub const SSH_CONTROL: &str = "host.ssh.permit-root-login";
/// The catalogued title of the SSH root-login control.
pub const SSH_CONTROL_TITLE: &str = "Disallow SSH root login";
/// The rule whose FAIL records the SSH root-login gap.
pub const SSH_RULE: &str = "host.ssh.detect-permit-root-login";
/// The framework the SSH root-login control belongs to.
pub const SSH_FRAMEWORK: &str = "iso-27001";
/// The SSH framework's catalog version.
pub const SSH_FRAMEWORK_VERSION: &str = "2022";
/// The SSH framework's source URL, rendered on its gap's Gaps row.
pub const SSH_FRAMEWORK_URL: &str = "https://www.iso.org/standard/27001";
/// The non-CWE framework reference the SSH root-login control maps to.
pub const SSH_CONTROL_REFERENCE: &str = "iso-27001:2022:A.8.2";

/// Builds one consent `ControlResult` for `rule_id` at `status`, carrying the
/// control's catalogued severity, weight, and evidence id from the Background.
#[must_use]
pub fn consent_result(rule_id: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(CONTROL)
        .rule_id(rule_id)
        .status(status)
        .severity("major")
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Non-essential tracker loaded without recorded consent.");
    }
    builder
        .build()
        .expect("the consent fixture result validates")
}

/// Builds a `ControlResult` for an arbitrary control/rule at `status` with the
/// given severity, for corpora that span more than the single consent control.
#[must_use]
pub fn control_result(
    control_id: &str,
    rule_id: &str,
    severity: &str,
    status: Status,
) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id(control_id)
        .rule_id(rule_id)
        .status(status)
        .severity(severity)
        .weight(8)
        .evidence_refs(["ev-0001"])
        .executed_at(EXECUTED_AT)
        .execution_metadata("engine_version=0.3.0");
    if status != Status::Pass {
        builder = builder.reason("Observed during the mixed compliance run.");
    }
    builder.build().expect("the mixed fixture result validates")
}

/// The "mixed-2026-06-24" run: gdpr-eprivacy and iso-27001 control results that
/// span two values of every filter dimension — framework (`gdpr-eprivacy` /
/// `iso-27001`), status (`FAIL` / `WARNING` / `SKIPPED`), severity (`major` /
/// `minor`), and applicability (`applicable` / `not applicable`, the latter from
/// the SKIPPED control). Its Gaps are the FAIL and WARNING results.
#[must_use]
pub fn mixed_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_framework("iso-27001", "2022", "https://www.iso.org/standard/27001")
        .with_control_result(
            FRAMEWORK,
            control_result(CONTROL, TRACKER_RULE, "major", Status::Fail),
        )
        .with_control_result(
            "iso-27001",
            control_result(
                "host.ssh.weak-crypto",
                "host.ssh.detect-weak-crypto",
                "minor",
                Status::Warning,
            ),
        )
        .with_control_result(
            "iso-27001",
            control_result(
                "host.ssh.protocol-v1",
                "host.ssh.detect-protocol-v1",
                "major",
                Status::Skipped,
            ),
        )
}

/// The canonical "shopfront-2026-06-24" consent corpus: the gdpr-eprivacy
/// framework, its catalogued `consent.tracker.prior-consent` control, that
/// control's FAIL + PASS results, and the `ev-0001` evidence record those
/// results reference, collected from the built asset `dist/main.js`.
#[must_use]
pub fn consent_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
        .with_evidence("ev-0001", "dist/main.js")
}

/// The consent corpus with its two control results supplied in the opposite
/// order, for asserting the export's column layout is independent of input order.
#[must_use]
pub fn consent_corpus_results_shuffled() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, consent_result(CMP_RULE, Status::Pass))
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_evidence("ev-0001", "dist/main.js")
}

/// The "gap-reference-2026-06-24" corpus: two catalogued controls that each fail,
/// under two different frameworks, so the Gaps sheet renders each gap's own
/// framework reference and source URL. The consent control maps to reference
/// `gdpr-eprivacy:2016-679:Art.7` under the gdpr-eprivacy framework, and the SSH
/// root-login control to `iso-27001:2022:A.8.2` under iso-27001 — two distinct
/// non-CWE references, neither a shared constant nor a CWE fallback.
#[must_use]
pub fn gap_references_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL)
        .with_framework(SSH_FRAMEWORK, SSH_FRAMEWORK_VERSION, SSH_FRAMEWORK_URL)
        .with_control(
            FRAMEWORK,
            CONTROL,
            CONTROL_TITLE,
            "major",
            8,
            CONTROL_REFERENCE,
        )
        .with_control(
            SSH_FRAMEWORK,
            SSH_CONTROL,
            SSH_CONTROL_TITLE,
            "major",
            8,
            SSH_CONTROL_REFERENCE,
        )
        .with_control_result(FRAMEWORK, consent_result(TRACKER_RULE, Status::Fail))
        .with_control_result(
            SSH_FRAMEWORK,
            control_result(SSH_CONTROL, SSH_RULE, "major", Status::Fail),
        )
}

/// The "classified-evidence-2026-06-24" corpus: a persisted store holding two
/// classified evidence records the Evidence sheet must reduce to metadata — the
/// Secret `ev-0007`, collected from `.env.example:3`, and the Sensitive `ev-0008`,
/// collected from `config/users.yaml:12` — each carrying its `sha256:…` integrity
/// digest. The store already dropped each record's raw value, so the corpus holds
/// only the metadata a redacted Evidence row shows; no raw value is present to leak.
#[must_use]
pub fn classified_evidence_corpus() -> Corpus {
    Corpus::new(EXECUTED_AT)
        .with_classified_evidence(
            "ev-0007",
            "config",
            ".env.example:3",
            Classification::Secret,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .with_classified_evidence(
            "ev-0008",
            "config",
            "config/users.yaml:12",
            Classification::Sensitive,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
}

/// A large corpus of 120 control results under the consent framework, each with a
/// distinct control and rule id and a status cycling through the five outcomes,
/// for asserting the export stays deterministic at scale.
#[must_use]
pub fn large_corpus() -> Corpus {
    let mut corpus =
        Corpus::new(EXECUTED_AT).with_framework(FRAMEWORK, FRAMEWORK_VERSION, FRAMEWORK_URL);
    for index in 0..120 {
        let control = format!("control.{index:03}");
        let rule = format!("rule.{index:03}");
        let status = match index % 5 {
            0 => Status::Pass,
            1 => Status::Fail,
            2 => Status::Warning,
            3 => Status::Skipped,
            _ => Status::Error,
        };
        corpus =
            corpus.with_control_result(FRAMEWORK, control_result(&control, &rule, "major", status));
    }
    corpus
}
