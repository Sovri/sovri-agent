// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the `@e2e` `sovri-agent scan` acceptance tests.
//!
//! These scenarios spawn the compiled binary and assert on its stdout, stderr,
//! and exit code. They stay on the host-independent surfaces — argument parsing,
//! catalog load, catalog validation, and selection resolution — which all resolve
//! before any host acquisition, so the binary reaches its verdict without reading
//! the machine it runs on. The module is standard-library only, so an `@e2e` test
//! crate compiles even while the `scan` module the `@use-case` crates need does
//! not yet exist.
#![allow(dead_code)]

use std::process::Command;

/// The checked-in five-control `cis-linux` catalog directory.
pub const CATALOG: &str = "tests/fixtures/cis-linux";
/// A catalog that loads but fails validation (an unmapped control).
pub const INVALID_CATALOG: &str = "tests/fixtures/invalid-catalog";
/// A catalog directory that does not exist.
pub const MISSING_CATALOG: &str = "tests/fixtures/does-not-exist";

/// The captured result of one `sovri-agent scan` invocation.
pub struct Run {
    /// Everything the command wrote to standard output.
    pub stdout: String,
    /// Everything the command wrote to standard error.
    pub stderr: String,
    /// The process exit code, or `None` if the process was signalled.
    pub code: Option<i32>,
}

impl Run {
    /// Standard output and standard error concatenated, for substring checks that
    /// do not care which stream carried the text.
    #[must_use]
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }

    /// Whether standard output carries a control result listing. Every control id
    /// in the fixtures is prefixed `host.` or `container.`, so their absence means
    /// the command printed no listing.
    #[must_use]
    pub fn printed_listing(&self) -> bool {
        self.stdout.contains("host.") || self.stdout.contains("container.")
    }
}

/// Run `sovri-agent scan` with `args` and capture its output.
///
/// # Panics
/// Panics if the binary cannot be launched.
#[must_use]
pub fn scan(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_sovri-agent"))
        .arg("scan")
        .args(args)
        .output()
        .expect("the sovri-agent binary launches");
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code(),
    }
}
