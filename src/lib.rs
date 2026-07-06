// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! sovri-agent library — the crate the V0.4 Linux scanners plug into.
//!
//! Bootstraps the agent on the pinned `sovri-sdk` engine (MAT-122):
//!
//! - [`scanners`] — a host-acquisition / pure-evaluation
//!   [`Scanner`](scanners::Scanner) split, plus a rule-id
//!   [`Registry`](scanners::Registry) that the agent hands to
//!   [`sovri_sdk::Engine::execute`] as a [`sovri_sdk::RuleEvaluator`].
//! - [`controls`] — the self-contained selftest control that proves the engine
//!   seam end to end.
//! - [`evidence`] — a relay re-exporting the `sovri-sdk` evidence contract.
//! - [`report`] — the deterministic PDF report renderer over persisted evidence.
//! - [`scan`] — the `sovri-agent scan` command that runs a catalog's controls
//!   against the host scanners and reports the outcome.
//!
//! Everything runs offline: the standard library only, no network.

pub mod controls;
pub mod evidence;
pub mod report;
pub mod scan;
pub mod scanners;

/// Returns the version of the `sovri-sdk` contract the agent links against.
///
/// The value comes from the linked SDK ([`sovri_sdk::SDK_VERSION`]), never a
/// hardcoded copy, so it always tracks the pinned dependency.
#[must_use]
pub fn sdk_version() -> &'static str {
    sovri_sdk::SDK_VERSION
}
