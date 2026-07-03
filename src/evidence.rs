// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Evidence relay.
//!
//! Re-exports the `sovri-sdk` evidence contract so agent code and downstream
//! consumers speak one evidence vocabulary rather than redefining the auditable
//! proof types. The agent adds nothing here yet; V0.4 scanners attach evidence
//! through these re-exported types.

pub use sovri_sdk::{
    attach_evidence, collect_offline, Classification, Collection, Evidence, EvidenceBuilder,
    EvidenceCitation, EvidenceError, EvidenceKind, EvidenceLog, EvidenceSource, GapExplanation,
    EXCERPT_CAP_BYTES,
};
