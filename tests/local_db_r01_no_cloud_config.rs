// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! R-01 — local database creation never requires cloud configuration. Covers
//! issue #336.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sovri_agent::local_db::LocalDatabase;

const CHILD_DATABASE_PATH_ENV: &str = "SOVRI_LOCAL_DB_NO_CLOUD_CHILD_PATH";

struct TempDatabase {
    root: PathBuf,
    db_path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "sovri-agent-test-{}-{now}-{unique}",
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

#[test]
fn creation_never_requires_a_cloud_endpoint_or_secret() {
    // Given "SOVRI_ENDPOINT" is unset.
    let database = TempDatabase::new();
    let output = Command::new(env::current_exe().expect("test executable is available"))
        .arg("--exact")
        .arg("child_process_creates_database_without_cloud_config")
        .arg("--nocapture")
        .env(CHILD_DATABASE_PATH_ENV, database.path())
        .env_remove("SOVRI_ENDPOINT")
        // And "SOVRI_TOKEN" is unset.
        .env_remove("SOVRI_TOKEN")
        // When the operator opens the local database at "./tmp/sovri-mat-98.db".
        .output()
        .expect("child test process runs");

    let mut child_output = String::from_utf8_lossy(&output.stdout).to_string();
    child_output.push_str(&String::from_utf8_lossy(&output.stderr));
    let child_output = child_output.to_ascii_lowercase();

    assert!(
        !child_output.contains("cloud endpoint"),
        "local database creation mentioned a missing cloud endpoint: {child_output}"
    );
    assert!(
        !child_output.contains("secret"),
        "local database creation mentioned a missing secret: {child_output}"
    );

    // Then the operation succeeds.
    assert!(
        output.status.success(),
        "local database creation should succeed without cloud config: {child_output}"
    );
    assert!(database.path().exists(), "the local database was created");
}

#[test]
fn child_process_creates_database_without_cloud_config() {
    let Some(database_path) = env::var_os(CHILD_DATABASE_PATH_ENV) else {
        return;
    };

    let opened = LocalDatabase::open(Path::new(&database_path))
        .expect("local database creation succeeds without cloud config");
    assert_eq!(opened.schema_version(), 1);
}
