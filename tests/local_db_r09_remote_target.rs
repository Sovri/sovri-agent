// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-09 -- remote database targets are rejected before external I/O. Covers #367.

use std::error::Error as _;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;

const REMOTE_TARGET: &str = "postgres://cloud.sovri.example/mat-98";

struct IsolatedWorkingDirectory {
    original: PathBuf,
    root: PathBuf,
}

impl IsolatedWorkingDirectory {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r09-remote-target-{}-{now}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("the isolated working directory is created");
        let original = std::env::current_dir().expect("the original working directory is known");
        std::env::set_current_dir(&root).expect("the isolated working directory is selected");
        IsolatedWorkingDirectory { original, root }
    }
}

impl Drop for IsolatedWorkingDirectory {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
        let _ = fs::remove_dir_all(&self.root);
        std::env::remove_var("SOVRI_ENDPOINT");
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
fn remote_database_targets_are_rejected_before_any_network_attempt() {
    let _working_directory = IsolatedWorkingDirectory::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("the network sentinel binds");
    std::env::set_var(
        "SOVRI_ENDPOINT",
        format!(
            "http://{}",
            listener
                .local_addr()
                .expect("the network sentinel exposes its address")
        ),
    );

    // When the operator asks to open database target "postgres://cloud.sovri.example/mat-98".
    let Err(error) = LocalDatabase::open(REMOTE_TARGET) else {
        panic!("the remote database target must be rejected");
    };

    // Then the database target is rejected as non-local.
    let message = error.to_string();
    assert!(
        message.contains("non-local") && message.contains(REMOTE_TARGET),
        "unexpected remote-target error: {message}"
    );
    // And no network connection is opened.
    assert_no_connection(&listener);
    // And no third-party service is contacted.
    assert!(
        error.source().is_none(),
        "local target validation must not wrap an external service error"
    );
}
