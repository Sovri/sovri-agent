// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — opening a missing SQLite database creates the file and applies the
//! initial local schema without relying on a network endpoint. Covers issue #333.

use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::local_db::{LocalDatabase, INITIAL_SCHEMA_VERSION};

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r01-{}-{unique}",
            std::process::id()
        ));
        TempDatabase {
            db_path: root.join("tmp").join("sovri-mat-98.db"),
            root,
        }
    }

    fn path(&self) -> &Path {
        &self.db_path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("the listener can be made nonblocking");
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected listener error while checking network use: {error}"),
        Ok((_, address)) => panic!("unexpected outbound connection reached {address}"),
    }
}

#[test]
fn opening_a_missing_database_creates_it_and_applies_the_initial_schema() {
    let database = TempDatabase::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("local network sentinel binds");
    let endpoint = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("the sentinel exposes its bound address")
    );
    std::env::set_var("SOVRI_ENDPOINT", endpoint);

    // When the operator opens the local database at "./tmp/sovri-mat-98.db".
    let opened = LocalDatabase::open(database.path()).expect("the local database opens");

    // Then a SQLite database file exists at "./tmp/sovri-mat-98.db".
    assert!(
        database.path().exists(),
        "the SQLite database file is created"
    );

    // And the database exposes schema version 1.
    assert_eq!(opened.schema_version(), INITIAL_SCHEMA_VERSION);
    assert_eq!(opened.schema_version(), 1);

    // And the schema includes tables for scan runs, frameworks, controls, control
    // results, gaps, evidence metadata, score summaries, and exports.
    let tables = opened.schema_tables().expect("schema tables can be read");
    for expected in [
        "scan_runs",
        "frameworks",
        "controls",
        "control_results",
        "compliance_gaps",
        "evidence_metadata",
        "score_summaries",
        "exports",
    ] {
        assert!(
            tables.iter().any(|table| table == expected),
            "missing expected table {expected}; got {tables:?}"
        );
    }

    // And no outbound network call is performed.
    assert_no_connection(&listener);
    std::env::remove_var("SOVRI_ENDPOINT");
}
