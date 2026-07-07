// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! `SpreadsheetML` 2003 compliance-matrix export.
//!
//! Emits a hand-written `SpreadsheetML` 2003 flat `<Workbook>` XML string from a
//! persisted compliance corpus, so an auditor can open the compliance results as
//! a filterable spreadsheet instead of raw JSON. The exporter consumes the
//! already-derived corpus; it never re-runs a scanner or recomputes a score, and
//! it links no third-party runtime dependency — the XML is emitted by hand.

use sovri_sdk::Status;

/// XML declaration that opens the workbook document.
const XML_DECLARATION: &str = r#"<?xml version="1.0"?>"#;
/// Processing instruction that makes a spreadsheet application open the flat XML
/// as an Excel workbook.
const MSO_APPLICATION_PROCESSING_INSTRUCTION: &str = r#"<?mso-application progid="Excel.Sheet"?>"#;
/// `SpreadsheetML` namespace that identifies the document as a workbook.
const SPREADSHEET_NAMESPACE: &str = "urn:schemas-microsoft-com:office:spreadsheet";
/// Office namespace the workbook's document properties are qualified with.
const OFFICE_NAMESPACE: &str = "urn:schemas-microsoft-com:office:office";

/// The Results worksheet's name — the sheet that carries one row per control
/// result. Named once so the emission loop can single it out from its siblings.
const RESULTS_WORKSHEET: &str = "Results";

/// The Frameworks worksheet's name — the sheet that lists each framework's
/// version and source URL. Named once so the emission loop can single it out.
const FRAMEWORKS_WORKSHEET: &str = "Frameworks";

/// The worksheets the workbook always carries, in their fixed emission order.
///
/// Every export lays out these six sheets so a reader can filter the compliance
/// matrix section by section. Later scenarios fill each sheet's rows; the sheet
/// itself is always present with an empty `<Table>`, even when its section of
/// the corpus is empty. The order is fixed so the output stays deterministic.
const WORKSHEET_NAMES: [&str; 6] = [
    "Controls",
    RESULTS_WORKSHEET,
    "Gaps",
    "Evidence",
    FRAMEWORKS_WORKSHEET,
    "Summary",
];

/// A persisted compliance corpus a workbook is exported from.
///
/// The corpus is the already-derived, hashed output of a scan run, read from the
/// persisted store and never recomputed here. It carries the run's fixed
/// generated date, the control results the Results sheet renders, and the
/// frameworks the Frameworks sheet lists; later sheets read their rows from the
/// same corpus.
pub struct Corpus {
    executed_at: String,
    results: Vec<Status>,
    frameworks: Vec<Framework>,
}

/// A compliance framework the corpus covers — its id, catalog version, and the
/// source URL its controls are drawn from.
struct Framework {
    id: String,
    version: String,
    source_url: String,
}

impl Corpus {
    /// Builds a corpus for a run with the given fixed executed-at timestamp.
    ///
    /// The timestamp becomes the workbook's generated date, so the export stays
    /// deterministic and never reads the wall clock. The corpus starts empty;
    /// add control results with [`Corpus::with_result`] and frameworks with
    /// [`Corpus::with_framework`].
    #[must_use]
    pub fn new(executed_at: impl Into<String>) -> Self {
        Self {
            executed_at: executed_at.into(),
            results: Vec::new(),
            frameworks: Vec::new(),
        }
    }

    /// Adds a control result carrying the given status to the corpus.
    ///
    /// Every result the corpus holds renders as one row on the Results sheet, so
    /// the export lays out the run's outcomes read from the persisted corpus,
    /// never re-run. The builder is chainable so a corpus can be assembled
    /// inline.
    #[must_use]
    pub fn with_result(mut self, status: Status) -> Self {
        self.results.push(status);
        self
    }

    /// Adds a framework the corpus covers, rendered as one row on the Frameworks
    /// sheet.
    ///
    /// The corpus records each framework's catalog version and source URL as read
    /// from the persisted run, so the export lays them out without recomputing
    /// anything. The builder is chainable.
    #[must_use]
    pub fn with_framework(
        mut self,
        id: impl Into<String>,
        version: impl Into<String>,
        source_url: impl Into<String>,
    ) -> Self {
        self.frameworks.push(Framework {
            id: id.into(),
            version: version.into(),
            source_url: source_url.into(),
        });
        self
    }
}

/// Exports the compliance corpus as a `SpreadsheetML` 2003 flat `<Workbook>`.
///
/// The returned string is a self-contained `SpreadsheetML` document: the XML
/// declaration, the `mso-application` processing instruction that opens it in a
/// spreadsheet application, and a `<Workbook>` root that records the corpus's
/// fixed generated date and carries the six named worksheets (Controls, Results,
/// Gaps, Evidence, Frameworks, Summary) the compliance matrix is laid out
/// across.
#[must_use]
pub fn export(corpus: &Corpus) -> String {
    let created = &corpus.executed_at;
    let mut worksheets = String::new();
    for name in WORKSHEET_NAMES {
        worksheets.push_str("<Worksheet ss:Name=\"");
        worksheets.push_str(name);
        worksheets.push_str("\">\n");
        if name == RESULTS_WORKSHEET {
            push_results_table(&mut worksheets, &corpus.results);
        } else if name == FRAMEWORKS_WORKSHEET {
            push_frameworks_table(&mut worksheets, &corpus.frameworks);
        } else {
            worksheets.push_str("<Table/>\n");
        }
        worksheets.push_str("</Worksheet>\n");
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

/// Appends the Results sheet's `<Table>` — one `<Row>` per control result, each
/// a single string cell carrying the result's status label (`PASS`, `FAIL`,
/// `WARNING`, `SKIPPED`, or `ERROR`). An empty corpus keeps the self-closing
/// `<Table/>`, so the sheet stays present but carries no rows.
fn push_results_table(out: &mut String, results: &[Status]) {
    if results.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for status in results {
        out.push_str("<Row>");
        push_string_cell(out, status.label());
        out.push_str("</Row>\n");
    }
    out.push_str("</Table>\n");
}

/// Appends the Frameworks sheet's `<Table>` — one `<Row>` per framework, with
/// cells for its id, catalog version, and source URL. An empty corpus keeps the
/// self-closing `<Table/>`.
fn push_frameworks_table(out: &mut String, frameworks: &[Framework]) {
    if frameworks.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for framework in frameworks {
        out.push_str("<Row>");
        push_string_cell(out, &framework.id);
        push_string_cell(out, &framework.version);
        push_string_cell(out, &framework.source_url);
        out.push_str("</Row>\n");
    }
    out.push_str("</Table>\n");
}

/// Appends one `<Cell>` holding `value` as an XML-escaped string datum.
fn push_string_cell(out: &mut String, value: &str) {
    out.push_str("<Cell><Data ss:Type=\"String\">");
    out.push_str(&xml_escape(value));
    out.push_str("</Data></Cell>");
}

/// Escapes the five XML metacharacters so a cell value can never break the
/// document structure or leak markup into the workbook.
fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
