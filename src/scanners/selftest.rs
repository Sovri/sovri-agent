// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The self-contained engine-wiring selftest scanner: a minimal [`Scanner`]
//! proving the acquisition/evaluation seam. Acquisition reads a trivial host
//! fact offline; evaluation is a pure function of the captured snapshot.

// `SelftestScanner` / `SelftestSnapshot` intentionally echo their module name.
#![allow(clippy::module_name_repetitions)]

use super::{AcquireError, Scanner, Verdict};

/// A captured host snapshot for the engine-wiring selftest: whether the wiring
/// sentinel was observed on the host.
#[derive(Debug, Clone, Copy)]
pub struct SelftestSnapshot {
    sentinel_present: bool,
}

impl SelftestSnapshot {
    /// A snapshot whose engine-wiring sentinel is present.
    #[must_use]
    pub fn present() -> Self {
        Self {
            sentinel_present: true,
        }
    }

    /// A snapshot whose engine-wiring sentinel is absent.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            sentinel_present: false,
        }
    }
}

/// The minimal in-repo scanner that proves the engine seam end to end. It reports
/// the selftest control satisfied when the wiring sentinel is present.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelftestScanner;

impl Scanner for SelftestScanner {
    type Snapshot = SelftestSnapshot;

    fn acquire(&self) -> Result<Self::Snapshot, AcquireError> {
        // Offline host read: the agent's own executable must resolve. This keeps
        // acquisition a real host access (standard library, no network) while
        // staying deterministic — the sentinel is the agent's own presence.
        let sentinel_present =
            std::env::current_exe()
                .map(|path| path.exists())
                .map_err(|error| {
                    AcquireError::new(format!("cannot resolve the current executable: {error}"))
                })?;
        Ok(SelftestSnapshot { sentinel_present })
    }

    fn evaluate(&self, snapshot: &Self::Snapshot) -> Verdict {
        if snapshot.sentinel_present {
            Verdict::Satisfied
        } else {
            Verdict::Finding
        }
    }
}
