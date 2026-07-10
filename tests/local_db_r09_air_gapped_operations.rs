// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 -- local database operations remain air-gapped. Covers #365.

use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;
use sovri_agent::matrix::Corpus;

const RUN_ID: &str = "shopfront-2026-06-24";
const EXECUTED_AT: &str = "2026-06-24T13:16:28Z";

struct TempFixture {
    root: PathBuf,
}

impl TempFixture {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r09-air-gap-{}-{now}-{unique}",
            std::process::id()
        ));
        TempFixture { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("tmp").join("sovri-mat-98.db")
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        std::env::remove_var("SOVRI_ENDPOINT");
        std::env::remove_var("SOVRI_TOKEN");
    }
}

fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("the network sentinel can be made nonblocking");
    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected sentinel error: {error}"),
        Ok((_, address)) => panic!("unexpected outbound connection reached {address}"),
    }
}

#[test]
fn open_write_and_query_succeed_with_network_denied() {
    // Given no network connection is available.
    let listener = TcpListener::bind("127.0.0.1:0").expect("the network sentinel binds");
    let endpoint = format!(
        "http://{}",
        listener
            .local_addr()
            .expect("the network sentinel exposes its address")
    );
    std::env::set_var("SOVRI_ENDPOINT", endpoint);
    std::env::remove_var("SOVRI_TOKEN");
    // And an open local database path "./tmp/sovri-mat-98.db".
    let fixture = TempFixture::new();
    // And the "shopfront-2026-06-24" consent corpus is available locally.
    let corpus = Corpus::new(EXECUTED_AT)
        .with_run_id(RUN_ID)
        .with_framework("gdpr-eprivacy", "2016-679", "")
        .with_control(
            "gdpr-eprivacy",
            "consent.tracker.prior-consent",
            "",
            "major",
            8,
            "",
        )
        .with_evidence("ev-0001", "dist/main.js");

    // When the operator opens the local database at "./tmp/sovri-mat-98.db".
    let mut database =
        LocalDatabase::open(fixture.database_path()).expect("the local database opens");
    // And the operator writes corpus "shopfront-2026-06-24".
    database
        .write_completed_corpus(&corpus)
        .expect("the local corpus write succeeds");
    // And the operator queries run "shopfront-2026-06-24".
    let runs = database
        .query_run(RUN_ID)
        .expect("the local run query succeeds");

    // Then the query returns run "shopfront-2026-06-24".
    assert_eq!(runs, [RUN_ID]);
    // And no outbound network call is attempted.
    assert_no_connection(&listener);
    // And no Sovri Cloud dependency is required.
    assert!(
        fixture.database_path().exists() && std::env::var_os("SOVRI_TOKEN").is_none(),
        "local operations complete without a cloud token"
    );
}
