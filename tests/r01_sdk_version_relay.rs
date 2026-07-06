// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance test for R-01 — the agent relays the SDK contract version.
//!
//! Mirrors `specs/mat-122-agent-crate-bootstrap/r01-sdk-version-relay.feature`.

use sovri_agent::sdk_version;

/// Scenario: The agent reports the linked SDK contract version.
#[test]
fn reports_the_linked_sdk_contract_version() {
    // Given the agent links the sovri-sdk contract at version "0.3.0"
    // When the agent reports its SDK contract version
    // Then the reported version is "0.3.0"
    assert_eq!(sdk_version(), "0.3.0");
}

/// Scenario: The reported version tracks the linked SDK, not a private copy.
#[test]
fn reported_version_tracks_the_linked_sdk() {
    // Given the agent links the sovri-sdk crate
    // When the agent reports its SDK contract version
    // Then the reported version equals the SDK's own SDK_VERSION
    assert_eq!(sdk_version(), sovri_sdk::SDK_VERSION);
    // And the reported version is not empty
    assert!(!sdk_version().is_empty());
}
