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

/// The worksheets the workbook always carries, in their fixed emission order.
///
/// Every export lays out these six sheets so a reader can filter the compliance
/// matrix section by section. Later scenarios fill each sheet's rows; the sheet
/// itself is always present with an empty `<Table>`, even when its section of
/// the corpus is empty. The order is fixed so the output stays deterministic.
const WORKSHEET_NAMES: [&str; 6] = [
    "Controls",
    "Results",
    "Gaps",
    "Evidence",
    "Frameworks",
    "Summary",
];

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
/// spreadsheet application, and a `<Workbook>` root that records the corpus's
/// fixed generated date and carries the six named worksheets (Controls,
/// Results, Gaps, Evidence, Frameworks, Summary) the compliance matrix is laid
/// out across.
#[must_use]
pub fn export(corpus: &Corpus) -> String {
    let created = &corpus.executed_at;
    let mut worksheets = String::new();
    for name in WORKSHEET_NAMES {
        worksheets.push_str("<Worksheet ss:Name=\"");
        worksheets.push_str(name);
        worksheets.push_str("\">\n<Table/>\n</Worksheet>\n");
    }
    format!(
        "{XML_DECLARATION}\n\
         {MSO_APPLICATION_PROCESSING_INSTRUCTION}\n\
         <Workbook xmlns=\"{SPREADSHEET_NAMESPACE}\" xmlns:ss=\"{SPREADSHEET_NAMESPACE}\">\n\
         <DocumentProperties xmlns=\"{OFFICE_NAMESPACE}\">\n\
         <Created>{created}</Created>\n\
         </DocumentProperties>\n\
         {worksheets}\
         </Workbook>\n"
    )
}
