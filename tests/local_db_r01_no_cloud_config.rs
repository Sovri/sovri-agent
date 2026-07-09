// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — local database creation never requires cloud configuration. Covers
//! issue #336.

use std::ffi::OsString;
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
            "sovri-agent-mat98-r01-no-cloud-config-{}-{unique}",
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

struct EnvVarRestore {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVarRestore {
    fn unset(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        EnvVarRestore { name, previous }
    }
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.name, previous);
        } else {
            std::env::remove_var(self.name);
        }
    }
}

#[test]
fn creation_never_requires_a_cloud_endpoint_or_secret() {
    // Given "SOVRI_ENDPOINT" is unset.
    let _endpoint = EnvVarRestore::unset("SOVRI_ENDPOINT");

    // And "SOVRI_TOKEN" is unset.
    let _token = EnvVarRestore::unset("SOVRI_TOKEN");
    let database = TempDatabase::new();

    // When the operator opens the local database at "./tmp/sovri-mat-98.db".
    let opened = LocalDatabase::open(database.path()).unwrap_or_else(|error| {
        let error_message = error.to_string().to_ascii_lowercase();
        assert!(
            !error_message.contains("cloud endpoint"),
            "local database creation mentioned a missing cloud endpoint: {error_message}"
        );
        assert!(
            !error_message.contains("secret"),
            "local database creation mentioned a missing secret: {error_message}"
        );
        panic!("local database creation should succeed without cloud config: {error_message}");
    });

    // Then the operation succeeds.
    assert!(database.path().exists(), "the local database was created");
    assert_eq!(opened.schema_version(), 1);
}
