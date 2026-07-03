// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The self-contained selftest control and its catalog.
//!
//! Decoupled from the CIS catalog (MAT-124) and from real host controls: a
//! minimal in-repo control whose only job is to prove the engine seam. The
//! control is self-contained, so it can be selected and executed by control id
//! with no framework mapping.

use sovri_sdk::{Catalog, Control, Rule};

/// Control id of the self-contained engine-wiring selftest.
pub const ENGINE_WIRING_CONTROL: &str = "agent.selftest.engine-wiring";

/// Rule id whose scanner reports the control satisfied, mapping to `PASS`.
pub const PRODUCES_RESULT_RULE: &str = "agent.selftest.produces-result";

/// Rule id whose scanner reports a finding under the `fail` policy, mapping to
/// `FAIL`.
pub const REPORTS_FINDING_RULE: &str = "agent.selftest.reports-finding";

/// Rule id intentionally left unregistered, so executing it yields an `ERROR`.
pub const UNWIRED_RULE: &str = "agent.selftest.unwired";

/// Builds the selftest catalog carrying `rule_ids` under the engine-wiring
/// control.
///
/// [`REPORTS_FINDING_RULE`] is given the `fail` result policy so a finding maps
/// to `FAIL`; the other rules use the default policy. The catalog has no
/// frameworks or mappings — the control is selected by id, which needs neither.
#[must_use]
pub fn selftest_catalog(rule_ids: &[&str]) -> Catalog {
    let control = Control::new(
        ENGINE_WIRING_CONTROL,
        "minor",
        1,
        "Wire the agent to the SDK engine.",
    );
    let rules = rule_ids
        .iter()
        .map(|&rule_id| {
            let rule = Rule::new(rule_id, ENGINE_WIRING_CONTROL, "static-analysis");
            if rule_id == REPORTS_FINDING_RULE {
                rule.with_result_policy("fail")
            } else {
                rule
            }
        })
        .collect();
    Catalog::new(Vec::new(), vec![control], rules, Vec::new())
}
