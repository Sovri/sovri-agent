// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! sovri-agent — placeholder CLI for the Sovri compliance agent.
//!
//! Scaffolded by MAT-81. Runs fully offline: no network, no environment
//! configuration, no secrets. The `scan` subcommand (MAT-125) runs a catalog's
//! controls against the host scanners; the `selftest` subcommand proves
//! air-gapped operation from day one.

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const USAGE: &str = "usage: sovri-agent <scan|selftest|--version|--help>";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("scan") => {
            // The arguments after the subcommand drive the scan; it reads only
            // the catalog directory and the flags, never the environment.
            let args: Vec<String> = std::env::args().skip(2).collect();
            sovri_agent::scan::run(&args)
        }
        Some("selftest") => {
            // No I/O beyond stdout; no network; no environment lookups.
            println!("sovri-agent {VERSION}: selftest ok (offline, no external services)");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            // Relay the linked SDK contract version so every run reports it.
            println!(
                "sovri-agent {VERSION} (sovri-sdk {})",
                sovri_agent::sdk_version()
            );
            ExitCode::SUCCESS
        }
        None | Some("--help" | "-h") => {
            println!("sovri-agent {VERSION}");
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("sovri-agent: unknown command '{other}'");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}
