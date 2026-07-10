// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — packaged migrations are sufficient to create the local `SQLite`
//! database on an air-gapped host. Covers issue #334.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sovri_agent::local_db::LocalDatabase;

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovri-agent-mat98-r01-packaged-{}-{unique}",
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
        std::env::remove_var("SOVRI_ENDPOINT");
        std::env::remove_var("SOVRI_TOKEN");
    }
}

#[test]
fn packaged_migrations_are_sufficient_on_an_air_gapped_host() {
    // Given the packaged agent contains migration "0001-initial".
    let database = TempDatabase::new();

    // And no external migration directory is available.
    let external_migrations = database.root.join("migrations");
    assert!(
        !external_migrations.exists(),
        "the test host provides no external migration directory"
    );
    std::env::set_var("SOVRI_ENDPOINT", "https://cloud.sovri.example/not-used");
    std::env::set_var("SOVRI_TOKEN", "fake-token-not-used");

    // When the operator opens the local database at "./tmp/sovri-mat-98.db".
    let opened = LocalDatabase::open(database.path()).expect("the local database opens");
    assert!(
        !external_migrations.exists(),
        "opening the local database did not create an external migration directory"
    );

    // Then migration "0001-initial" is applied from the packaged agent.
    let applied = opened
        .applied_migrations()
        .expect("applied migrations can be read");
    assert_eq!(applied, ["0001-initial"]);

    // And the database opens successfully without reading "SOVRI_ENDPOINT" or
    // "SOVRI_TOKEN".
    assert!(database.path().exists(), "the database was created locally");
    assert_eq!(opened.schema_version(), 1);
}
