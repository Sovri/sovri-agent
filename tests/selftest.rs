// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Acceptance-style test for the offline `selftest` placeholder command (R-04).

use std::process::Command;

#[test]
fn selftest_exits_zero_and_reports_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("selftest")
        .output()
        .expect("running sovri-agent selftest");

    assert!(output.status.success(), "selftest must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "selftest must print a status line reporting the agent version, got: {stdout}"
    );
}

#[test]
fn version_flag_reports_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("--version")
        .output()
        .expect("running sovri-agent --version");

    assert!(output.status.success(), "--version must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "--version must print the agent version, got: {stdout}"
    );
}

#[test]
fn unknown_command_exits_non_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("definitely-not-a-command")
        .output()
        .expect("running sovri-agent with an unknown command");

    assert!(!output.status.success(), "unknown command must fail");
}
