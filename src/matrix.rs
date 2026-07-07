// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! `SpreadsheetML` 2003 compliance-matrix export.
//!
//! Emits a hand-written `SpreadsheetML` 2003 flat `<Workbook>` XML string from a
//! persisted compliance corpus, so an auditor can open the compliance results as
//! a filterable spreadsheet instead of raw JSON. The exporter consumes the
//! already-derived corpus; it never re-runs a scanner or recomputes a score, and
//! it links no third-party runtime dependency — the XML is emitted by hand.

/// XML declaration that opens the workbook document.
const XML_DECLARATION: &str = r#"<?xml version="1.0"?>"#;
/// Processing instruction that makes a spreadsheet application open the flat XML
/// as an Excel workbook.
const MSO_APPLICATION_PROCESSING_INSTRUCTION: &str = r#"<?mso-application progid="Excel.Sheet"?>"#;
/// `SpreadsheetML` namespace that identifies the document as a workbook.
const SPREADSHEET_NAMESPACE: &str = "urn:schemas-microsoft-com:office:spreadsheet";
/// Office namespace the workbook's document properties are qualified with.
const OFFICE_NAMESPACE: &str = "urn:schemas-microsoft-com:office:office";

/// A persisted compliance corpus a workbook is exported from.
///
/// The corpus is the already-derived, hashed output of a scan run, read from the
/// persisted store and never recomputed here. This bootstrap carries the run's
/// fixed generated date; later sheets read their rows from the same corpus.
pub struct Corpus {
    executed_at: String,
}

impl Corpus {
    /// Builds a corpus for a run with the given fixed executed-at timestamp.
    ///
    /// The timestamp becomes the workbook's generated date, so the export stays
    /// deterministic and never reads the wall clock.
    #[must_use]
    pub fn new(executed_at: impl Into<String>) -> Self {
        Self {
            executed_at: executed_at.into(),
        }
    }
}

/// Exports the compliance corpus as a `SpreadsheetML` 2003 flat `<Workbook>`.
///
/// The returned string is a self-contained `SpreadsheetML` document: the XML
/// declaration, the `mso-application` processing instruction that opens it in a
/// spreadsheet application, and a `<Workbook>` root whose document properties
/// record the corpus's fixed generated date.
#[must_use]
pub fn export(corpus: &Corpus) -> String {
    format!(
        "{XML_DECLARATION}\n\
         {MSO_APPLICATION_PROCESSING_INSTRUCTION}\n\
         <Workbook xmlns=\"{SPREADSHEET_NAMESPACE}\">\n\
         <DocumentProperties xmlns=\"{OFFICE_NAMESPACE}\">\n\
         <Created>{}</Created>\n\
         </DocumentProperties>\n\
         </Workbook>\n",
        corpus.executed_at
    )
}
