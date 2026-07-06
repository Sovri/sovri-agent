// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! Evidence relay.
//!
//! Re-exports the `sovri-sdk` evidence contract so agent code and downstream
//! consumers speak one evidence vocabulary rather than redefining the auditable
//! proof types. The V0.4 scanners attach evidence through these types; the V0.5
//! scan hashes each record over its real bytes ([`content_digest`]) and persists
//! it to a content-addressed [`EvidenceStore`].

pub use sovri_sdk::{
    attach_evidence, collect_offline, content_digest, Classification, Collection, Digest, Evidence,
    EvidenceBuilder, EvidenceCitation, EvidenceError, EvidenceKind, EvidenceLog, EvidenceSource,
    EvidenceStore, GapExplanation, StoreError, EXCERPT_CAP_BYTES,
};
