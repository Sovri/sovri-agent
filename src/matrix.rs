// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! `SpreadsheetML` 2003 compliance-matrix export.
//!
//! Emits a hand-written `SpreadsheetML` 2003 flat `<Workbook>` XML string from a
//! persisted compliance corpus, so an auditor can open the compliance results as
//! a filterable spreadsheet instead of raw JSON. The exporter consumes the
//! already-derived corpus; it never re-runs a scanner or recomputes a score, and
//! it links no third-party runtime dependency — the XML is emitted by hand.

use sovri_sdk::{
    Catalog, ControlResult, ControlScore, EnvironmentScore, FrameworkScore, Mapping, Status,
    StatusCounts,
};

/// XML declaration that opens the workbook document.
const XML_DECLARATION: &str = r#"<?xml version="1.0"?>"#;
/// Processing instruction that makes a spreadsheet application open the flat XML
/// as an Excel workbook.
const MSO_APPLICATION_PROCESSING_INSTRUCTION: &str = r#"<?mso-application progid="Excel.Sheet"?>"#;
/// `SpreadsheetML` namespace that identifies the document as a workbook.
const SPREADSHEET_NAMESPACE: &str = "urn:schemas-microsoft-com:office:spreadsheet";
/// Office namespace the workbook's document properties are qualified with.
const OFFICE_NAMESPACE: &str = "urn:schemas-microsoft-com:office:office";
/// Excel namespace the `<AutoFilter>` range attribute is qualified with, so a
/// spreadsheet application reads the range as an R1C1 filter over the sheet.
const EXCEL_NAMESPACE: &str = "urn:schemas-microsoft-com:office:excel";

/// The Controls worksheet's name — the sheet that lists one row per catalogued
/// control the corpus evaluated. Named once so the emission loop can single it out.
const CONTROLS_WORKSHEET: &str = "Controls";

/// The Results worksheet's name — the sheet that carries one row per control
/// result. Named once so the emission loop can single it out from its siblings.
const RESULTS_WORKSHEET: &str = "Results";

/// The Gaps worksheet's name — the sheet that carries one row per compliance
/// gap, a control result that failed or warned and so requires review. Named
/// once so the emission loop can single it out from its siblings.
const GAPS_WORKSHEET: &str = "Gaps";

/// The Evidence worksheet's name — the sheet that carries one row per collected
/// evidence record, keyed by the stable evidence id a result or gap references.
/// Named once so the emission loop can single it out from its siblings.
const EVIDENCE_WORKSHEET: &str = "Evidence";

/// The Frameworks worksheet's name — the sheet that lists each framework's
/// version and source URL. Named once so the emission loop can single it out.
const FRAMEWORKS_WORKSHEET: &str = "Frameworks";

/// The Summary worksheet's name — the sheet that tallies results by framework and
/// status and names the MAT-87 score scopes. Named once so the emission loop can
/// single it out from its siblings.
const SUMMARY_WORKSHEET: &str = "Summary";

/// Label naming the control-score scope on the Summary sheet.
const CONTROL_SCORE_LABEL: &str = "Control score";
/// Label naming the framework-score scope on the Summary sheet.
const FRAMEWORK_SCORE_LABEL: &str = "Framework score";
/// Label naming the environment-score scope on the Summary sheet.
const ENVIRONMENT_SCORE_LABEL: &str = "Environment score";

/// Marker row text flagging the scores as incomplete because an errored control
/// was excluded from them. Emitted when any framework saw an `ERROR`.
const SCORES_INCOMPLETE_MARKER: &str = "Scores are incomplete: an ERROR result was excluded";

/// Explanatory row the Gaps sheet shows when the corpus recorded no gap, so an
/// empty Gaps section reads as "none observed" rather than a blank sheet.
const NO_GAPS_PLACEHOLDER: &str = "No potential gaps observed";

/// Explanatory row the Evidence sheet shows when the corpus collected no evidence
/// record, so an empty Evidence section reads as "none collected" rather than blank.
const NO_EVIDENCE_PLACEHOLDER: &str = "No evidence records were collected";

/// Integrity cell text for a record the store held without a digest, so the sheet
/// reads as a collection limitation rather than a blank cell.
const INTEGRITY_UNAVAILABLE: &str = "integrity metadata not available";

/// Explanatory row the Summary sheet shows when the corpus has no framework-scoped
/// result to score, so an empty Summary section reads as "no scores for this run".
const NO_SCORES_PLACEHOLDER: &str = "Scores are not available for this run";

/// Explanatory row the Summary sheet shows when the corpus holds no control result
/// at all, so the reason there is nothing to score is that nothing was evaluated.
const NO_CONTROLS_PLACEHOLDER: &str = "No controls were evaluated";

/// The statuses the Summary sheet tallies, in a fixed order so the count rows
/// stay deterministic across runs.
const SUMMARY_STATUS_ORDER: [Status; 5] = [
    Status::Pass,
    Status::Fail,
    Status::Warning,
    Status::Skipped,
    Status::Error,
];

/// The worksheets the workbook always carries, in their fixed emission order.
///
/// Every export lays out these six sheets so a reader can filter the compliance
/// matrix section by section. Later scenarios fill each sheet's rows; the sheet
/// itself is always present, carrying at least its documented header row even when
/// its section of the corpus is empty. The order is fixed so the output stays
/// deterministic.
const WORKSHEET_NAMES: [&str; 6] = [
    CONTROLS_WORKSHEET,
    RESULTS_WORKSHEET,
    GAPS_WORKSHEET,
    EVIDENCE_WORKSHEET,
    FRAMEWORKS_WORKSHEET,
    SUMMARY_WORKSHEET,
];

/// A persisted compliance corpus a workbook is exported from.
///
/// The corpus is the already-derived, hashed output of a scan run, read from the
/// persisted store and never recomputed here. It carries the run's fixed
/// generated date, the catalogued controls the Controls sheet lists, the control
/// results the Results sheet renders, the collected evidence the Evidence sheet
/// renders, and the frameworks the Frameworks sheet lists; later sheets read
/// their rows from the same corpus.
pub struct Corpus {
    executed_at: String,
    run_id: String,
    controls: Vec<Control>,
    results: Vec<ScopedResult>,
    evidence: Vec<Evidence>,
    frameworks: Vec<Framework>,
}

/// A control result together with the framework it was evaluated under.
///
/// The Summary sheet tallies and scores results per framework, so each result the
/// corpus holds records which framework produced it. A result added through
/// [`Corpus::with_result`] carries no framework: it is laid out on the Results
/// sheet but never counted or scored per framework.
struct ScopedResult {
    framework_id: Option<String>,
    result: ControlResult,
}

/// A compliance framework the corpus covers — its id, catalog version, and the
/// source URL its controls are drawn from.
struct Framework {
    id: String,
    version: String,
    source_url: String,
}

/// A catalogued control the corpus evaluated, carrying the fields that describe
/// it independent of any single result.
///
/// The Controls sheet lays out one row per catalogued control: the framework it
/// belongs to, its stable id, its catalogued title, and its severity and weight.
/// The title is catalog metadata a control result never carries, so the corpus
/// records the control here rather than deriving the Controls row from the run's
/// results. The control also carries its framework reference — the non-CWE
/// compliance reference (such as an article of the regulation) the Gaps sheet
/// renders for a gap on this control, so each gap shows its own reference rather
/// than a shared constant.
struct Control {
    framework_id: String,
    id: String,
    title: String,
    severity: String,
    weight: u32,
    reference: String,
}

/// The confidentiality classification a persisted evidence record carries.
///
/// The evidence store classified each record when it collected it and dropped the
/// raw value of a [`Classification::Secret`] or [`Classification::Sensitive`]
/// record, so that value never reaches the export. The classification decides the
/// record's redaction status on the Evidence sheet: a classified record renders
/// `redacted`, an unclassified record `none`.
#[derive(Clone, Copy)]
pub enum Classification {
    /// A secret value — a key, token, or credential — the store dropped, so the
    /// record's Evidence row is reduced to metadata and marked `redacted`.
    Secret,
    /// A sensitive value — personal or otherwise restricted data — the store
    /// dropped, so the record's Evidence row is reduced to metadata and marked
    /// `redacted`.
    Sensitive,
    /// An unclassified value the store kept in full, so the record's Evidence row
    /// is not redacted and its redaction status renders `none`.
    Unclassified,
}

/// A collected evidence record the corpus holds, carrying the stable id it is
/// filed under, its metadata, and the classification that decides its redaction
/// status.
///
/// The Evidence sheet lays out one row per record: its evidence id, so a Results
/// or Gaps row's evidence reference traces back to the record here; its kind and
/// the location it was collected at — a built asset, a config file, or another
/// artifact a finding was anchored to; its `sha256:…` integrity digest when the
/// store recorded one; and the redaction status its classification yields. A
/// classified record holds only this metadata — the store dropped its raw value on
/// disk, so no raw value is kept here to reach a cell. The record is read from the
/// persisted store, never recollected here.
struct Evidence {
    id: String,
    kind: String,
    location: String,
    integrity: String,
    classification: Classification,
}

impl Corpus {
    /// Builds a corpus for a run with the given fixed executed-at timestamp.
    ///
    /// The timestamp becomes the workbook's generated date, so the export stays
    /// deterministic and never reads the wall clock. The corpus starts empty; add
    /// catalogued controls with [`Corpus::with_control`], control results with
    /// [`Corpus::with_result`], collected evidence with [`Corpus::with_evidence`],
    /// and frameworks with [`Corpus::with_framework`].
    #[must_use]
    pub fn new(executed_at: impl Into<String>) -> Self {
        Self {
            executed_at: executed_at.into(),
            run_id: String::new(),
            controls: Vec::new(),
            results: Vec::new(),
            evidence: Vec::new(),
            frameworks: Vec::new(),
        }
    }

    /// The run's fixed executed-at timestamp — the value the exports carry as
    /// their generated date, so output stays deterministic and never reads the
    /// wall clock.
    #[must_use]
    pub fn executed_at(&self) -> &str {
        &self.executed_at
    }

    /// Records the stable id of the compliance run, the value the signed export's
    /// scan record carries so a downstream system can key off the run. A corpus
    /// built without one carries an empty run id, so existing callers are
    /// unaffected. The builder is chainable.
    #[must_use]
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = run_id.into();
        self
    }

    /// The stable id of the compliance run, carried on the signed export's scan
    /// record so each export traces back to its run. Empty when the corpus was
    /// built without one.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The MAT-87 environment score for the corpus's framework-scoped results — the
    /// pooled environment score plus the per-framework and per-control scores the
    /// SDK derives, grouped by the framework each result was evaluated under. The
    /// exporter carries this score; it never recomputes it here.
    #[must_use]
    pub fn environment_score(&self) -> EnvironmentScore {
        environment_score(&self.results)
    }

    /// The frameworks the corpus covers, each as its stable id, catalog version,
    /// and source URL, in the order they were added — the records the signed JSON
    /// export's frameworks section lists so a consumer can pin the exact catalog.
    #[must_use]
    pub fn frameworks(&self) -> Vec<(&str, &str, &str)> {
        self.frameworks
            .iter()
            .map(|framework| {
                (
                    framework.id.as_str(),
                    framework.version.as_str(),
                    framework.source_url.as_str(),
                )
            })
            .collect()
    }

    /// The stable ids of the catalogued controls the corpus evaluated, in the
    /// order they were added — the controls the signed JSON export lists, one
    /// record per id.
    #[must_use]
    pub fn control_ids(&self) -> Vec<&str> {
        self.controls
            .iter()
            .map(|control| control.id.as_str())
            .collect()
    }

    /// The catalogued controls, each as its framework id, control id, severity, and
    /// non-CWE framework reference, in the order they were added — the details a gap
    /// on a control resolves (its own reference and severity) by looking the control
    /// up by framework and control id.
    #[must_use]
    pub fn controls(&self) -> Vec<(&str, &str, &str, &str)> {
        self.controls
            .iter()
            .map(|control| {
                (
                    control.framework_id.as_str(),
                    control.id.as_str(),
                    control.severity.as_str(),
                    control.reference.as_str(),
                )
            })
            .collect()
    }

    /// The stable ids of the evidence records the corpus holds, in the order they
    /// were collected — the evidence the signed JSON export lists, one record per
    /// id.
    #[must_use]
    pub fn evidence_ids(&self) -> Vec<&str> {
        self.evidence
            .iter()
            .map(|record| record.id.as_str())
            .collect()
    }

    /// The corpus's control results, each paired with the framework it was
    /// evaluated under (`None` when it was added without one), in the order they
    /// were added — the source of the signed JSON export's results and gaps
    /// sections.
    #[must_use]
    pub fn scoped_results(&self) -> Vec<(Option<&str>, &ControlResult)> {
        self.results
            .iter()
            .map(|scoped| (scoped.framework_id.as_deref(), &scoped.result))
            .collect()
    }

    /// Adds a catalogued control the corpus evaluated, rendered as one row on the
    /// Controls sheet.
    ///
    /// The Controls sheet lays out the catalogued fields that describe a control —
    /// the framework it belongs to, its stable id, its title, severity, and
    /// weight — as read from the persisted catalog, never recomputed here. The
    /// title is catalog metadata a control result does not carry, so the corpus
    /// records it here. The control's framework `reference` — its non-CWE
    /// compliance reference — is recorded too, so a gap on this control renders
    /// its own reference on the Gaps sheet. The builder is chainable.
    #[must_use]
    pub fn with_control(
        mut self,
        framework_id: impl Into<String>,
        control_id: impl Into<String>,
        title: impl Into<String>,
        severity: impl Into<String>,
        weight: u32,
        reference: impl Into<String>,
    ) -> Self {
        self.controls.push(Control {
            framework_id: framework_id.into(),
            id: control_id.into(),
            title: title.into(),
            severity: severity.into(),
            weight,
            reference: reference.into(),
        });
        self
    }

    /// Adds a bare control result carrying the given status to the corpus.
    ///
    /// Every result the corpus holds renders as one row on the Results sheet, so
    /// the export lays out the run's outcomes read from the persisted corpus,
    /// never re-run. A bare result carries no framework, so it is laid out on the
    /// Results sheet but not counted or scored per framework on the Summary sheet;
    /// use [`Corpus::with_control_result`] to add a framework-scoped result. The
    /// builder is chainable so a corpus can be assembled inline.
    #[must_use]
    pub fn with_result(mut self, status: Status) -> Self {
        let result = minimal_result(&self.executed_at, status);
        self.results.push(ScopedResult {
            framework_id: None,
            result,
        });
        self
    }

    /// Adds a control result evaluated under `framework_id` to the corpus.
    ///
    /// The result renders as one row on the Results sheet and feeds the Summary
    /// sheet, where it is counted by status and folded into the MAT-87 control,
    /// framework, and environment scores, grouped by the framework it was
    /// evaluated under. Those scores are consumed from the SDK, never recomputed
    /// here. The builder is chainable.
    #[must_use]
    pub fn with_control_result(
        mut self,
        framework_id: impl Into<String>,
        result: ControlResult,
    ) -> Self {
        self.results.push(ScopedResult {
            framework_id: Some(framework_id.into()),
            result,
        });
        self
    }

    /// Adds a collected evidence record the corpus holds, rendered as one row on
    /// the Evidence sheet.
    ///
    /// The Evidence sheet lays out the record's stable evidence id — the id a
    /// Results or Gaps row references to trace a finding back to its evidence —
    /// and the location the evidence was collected from, as read from the
    /// persisted store and never recollected here. The record is unclassified: it
    /// carries no kind or integrity digest, and its redaction status renders
    /// `none`. Use [`Corpus::with_classified_evidence`] for a record the store
    /// classified and reduced to metadata. The builder is chainable.
    #[must_use]
    pub fn with_evidence(
        mut self,
        evidence_id: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        self.evidence.push(Evidence {
            id: evidence_id.into(),
            kind: String::new(),
            location: location.into(),
            integrity: String::new(),
            classification: Classification::Unclassified,
        });
        self
    }

    /// Adds an unclassified evidence record that carries an integrity digest,
    /// rendered as one row on the Evidence sheet.
    ///
    /// Like [`Corpus::with_evidence`] the record is unclassified — the store kept
    /// its value, so its redaction status renders `none` — but it also carries the
    /// `kind` the store recorded and the `sha256:…` `integrity` digest the
    /// content-addressed store filed it under, so its Evidence row shows the digest
    /// read from the store rather than an empty cell. No raw value is taken or held
    /// here. Use [`Corpus::with_classified_evidence`] for a record the store
    /// classified and reduced to metadata. The builder is chainable.
    #[must_use]
    pub fn with_evidence_digest(
        mut self,
        evidence_id: impl Into<String>,
        kind: impl Into<String>,
        location: impl Into<String>,
        integrity: impl Into<String>,
    ) -> Self {
        self.evidence.push(Evidence {
            id: evidence_id.into(),
            kind: kind.into(),
            location: location.into(),
            integrity: integrity.into(),
            classification: Classification::Unclassified,
        });
        self
    }

    /// Adds a classified evidence record the store reduced to metadata, rendered
    /// as one row on the Evidence sheet.
    ///
    /// A record the store classified as [`Classification::Secret`] or
    /// [`Classification::Sensitive`] had its raw value dropped on disk, so the
    /// corpus holds only its metadata — the stable evidence id, the `kind`, the
    /// `location` it was collected from, and its `sha256:…` `integrity` digest —
    /// and its Evidence row renders a `redacted` redaction status. No raw value is
    /// taken or held here, so none can reach a cell. The builder is chainable.
    #[must_use]
    pub fn with_classified_evidence(
        mut self,
        evidence_id: impl Into<String>,
        kind: impl Into<String>,
        location: impl Into<String>,
        classification: Classification,
        integrity: impl Into<String>,
    ) -> Self {
        self.evidence.push(Evidence {
            id: evidence_id.into(),
            kind: kind.into(),
            location: location.into(),
            integrity: integrity.into(),
            classification,
        });
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
    let created = xml_escape(&corpus.executed_at);
    let mut worksheets = String::new();
    for name in WORKSHEET_NAMES {
        worksheets.push_str("<Worksheet ss:Name=\"");
        worksheets.push_str(name);
        worksheets.push_str("\">\n");
        if name == CONTROLS_WORKSHEET {
            push_controls_table(&mut worksheets, &corpus.controls);
        } else if name == RESULTS_WORKSHEET {
            push_results_table(&mut worksheets, &corpus.results);
        } else if name == GAPS_WORKSHEET {
            push_gaps_table(
                &mut worksheets,
                &corpus.results,
                &corpus.controls,
                &corpus.frameworks,
            );
        } else if name == EVIDENCE_WORKSHEET {
            push_evidence_table(&mut worksheets, &corpus.evidence);
        } else if name == FRAMEWORKS_WORKSHEET {
            push_frameworks_table(&mut worksheets, &corpus.frameworks);
        } else if name == SUMMARY_WORKSHEET {
            push_summary_table(&mut worksheets, &corpus.results);
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

/// Builds a bare control result carrying `status`, with placeholder identity
/// fields, so a [`Corpus::with_result`] status can be laid out on the Results
/// sheet through the same `ControlResult` the framework-scoped path uses. The
/// placeholder control leaves the result unmapped, so it never joins a
/// per-framework tally or score.
fn minimal_result(executed_at: &str, status: Status) -> ControlResult {
    let mut builder = ControlResult::builder()
        .control_id("")
        .rule_id("")
        .status(status)
        .severity("")
        .weight(0)
        .evidence_refs(std::iter::empty::<&str>())
        .executed_at(executed_at)
        .execution_metadata("");
    if status != Status::Pass {
        builder = builder.reason("status recorded for the Results sheet");
    }
    builder
        .build()
        .expect("the bare Results-sheet result validates")
}

/// The Controls sheet's documented column headers, in their fixed order. The
/// header row names these columns and each data row carries one cell per column.
const CONTROLS_HEADER: [&str; 7] = [
    "Framework",
    "Control",
    "Title",
    "Severity",
    "Weight",
    "Applicability",
    "Applicability reason",
];

/// The Results sheet's documented column headers, in their fixed order.
const RESULTS_HEADER: [&str; 9] = [
    "Framework",
    "Control",
    "Rule",
    "Status",
    "Severity",
    "Score impact",
    "Evidence ids",
    "Remediation",
    "Applicability",
];

/// The Gaps sheet's documented column headers, in their fixed order.
const GAPS_HEADER: [&str; 10] = [
    "Gap id",
    "Framework",
    "Control",
    "Rule",
    "Reference",
    "Source URL",
    "Severity",
    "Gap type",
    "Evidence ids",
    "Remediation",
];

/// The Evidence sheet's documented column headers, in their fixed order.
const EVIDENCE_HEADER: [&str; 6] = [
    "Evidence id",
    "Type",
    "Location",
    "Collector",
    "Integrity",
    "Redaction status",
];

/// The Frameworks sheet's documented column headers, in their fixed order.
const FRAMEWORKS_HEADER: [&str; 3] = ["Framework", "Version", "Source URL"];

/// The Summary sheet's documented column headers, in their fixed order. They name
/// the per-framework status tally; the MAT-87 score-scope rows sit below it as
/// labelled rows, not under this tabular header.
const SUMMARY_HEADER: [&str; 3] = ["Framework", "Status", "Count"];

/// Appends one `<Row>` carrying `cells` as XML-escaped string data — one `<Cell>`
/// per value, in order — so a sheet's header row and its data rows stay aligned to
/// the same documented columns.
fn push_row(out: &mut String, cells: &[&str]) {
    out.push_str("<Row>");
    for cell in cells {
        push_string_cell(out, cell);
    }
    out.push_str("</Row>\n");
}

/// Appends an empty section's `<Table>` — its documented `header` row so a reader
/// still sees the section's columns, then, when the section names one, a single
/// explanatory `placeholder` row that says why the section is empty. This keeps an
/// absent section a present sheet with its header, never a bare self-closing
/// `<Table/>` a reader could mistake for a missing or broken sheet.
fn push_empty_table(out: &mut String, header: &[&str], placeholder: Option<&str>) {
    out.push_str("<Table>\n");
    push_row(out, header);
    if let Some(text) = placeholder {
        push_row(out, &[text]);
    }
    out.push_str("</Table>\n");
}

/// Appends an `<AutoFilter>` element whose range spans the header row (row 1)
/// across every documented column and down to the last data row, so a spreadsheet
/// application shows a filter dropdown on each column when it opens the sheet. The
/// range is fixed by the sheet's shape — `row_count` rows by `column_count`
/// columns in R1C1 notation — so it stays byte-identical across runs.
fn push_autofilter(out: &mut String, row_count: usize, column_count: usize) {
    out.push_str("<AutoFilter x:Range=\"R1C1:R");
    out.push_str(&row_count.to_string());
    out.push('C');
    out.push_str(&column_count.to_string());
    out.push_str("\" xmlns:x=\"");
    out.push_str(EXCEL_NAMESPACE);
    out.push_str("\"/>\n");
}

/// The applicability a Results row records for `status`: a `SKIPPED` control was
/// not applicable to the target, and any other status was applicable to it.
fn applicability_for(status: Status) -> &'static str {
    if status == Status::Skipped {
        "not applicable"
    } else {
        "applicable"
    }
}

/// The redaction status an evidence record of `classification` renders on its
/// Evidence row: a `Secret` or `Sensitive` record was reduced to metadata, so its
/// row is `redacted`; an unclassified record kept its value, so its row is `none`.
fn redaction_status(classification: Classification) -> &'static str {
    match classification {
        Classification::Secret | Classification::Sensitive => "redacted",
        Classification::Unclassified => "none",
    }
}

/// Appends the Controls sheet's `<Table>` — the documented header row, then one
/// `<Row>` per catalogued control carrying a cell for each documented column: the
/// framework it belongs to, its control id, catalogued title, severity, and
/// weight, then its applicability (`applicable` until a later rule models an
/// exclusion) and an empty applicability reason. The populated table is followed
/// by an `<AutoFilter>` spanning its header row so the sheet opens filterable. A
/// corpus with no catalogued control emits the documented header row alone, so the
/// sheet stays present with its columns and never invents a control.
fn push_controls_table(out: &mut String, controls: &[Control]) {
    if controls.is_empty() {
        push_empty_table(out, &CONTROLS_HEADER, None);
        return;
    }
    out.push_str("<Table>\n");
    push_row(out, &CONTROLS_HEADER);
    for control in controls {
        let weight = control.weight.to_string();
        push_row(
            out,
            &[
                &control.framework_id,
                &control.id,
                &control.title,
                &control.severity,
                &weight,
                "applicable",
                "",
            ],
        );
    }
    out.push_str("</Table>\n");
    push_autofilter(out, controls.len() + 1, CONTROLS_HEADER.len());
}

/// The corpus results ordered for reporting — by control id, then rule id — so a
/// results-derived sheet lays its data rows out in a stable, total order that does
/// not depend on the order the results were supplied to the [`Corpus`]. The order
/// is taken over references, so the corpus is never mutated.
fn results_in_reporting_order(results: &[ScopedResult]) -> Vec<&ScopedResult> {
    let mut ordered: Vec<&ScopedResult> = results.iter().collect();
    ordered.sort_by(|a, b| {
        a.result
            .control_id()
            .cmp(b.result.control_id())
            .then_with(|| a.result.rule_id().cmp(b.result.rule_id()))
    });
    ordered
}

/// Appends the Results sheet's `<Table>` — the documented header row, then one
/// `<Row>` per control result carrying a cell for each documented column: the
/// framework it was scoped under (empty when unscoped), the control and rule ids
/// that trace it to the corpus, its status label (`PASS`, `FAIL`, `WARNING`,
/// `SKIPPED`, or `ERROR`), its severity, an empty score impact, the evidence ids
/// it references, an empty remediation, and its applicability (`not applicable`
/// for a `SKIPPED` result, else `applicable`). The empty columns are filled by
/// later rules. The populated table is followed by an `<AutoFilter>` spanning its
/// header row. An empty corpus emits the documented header row alone, so the sheet
/// stays present with its columns but no data row.
fn push_results_table(out: &mut String, results: &[ScopedResult]) {
    if results.is_empty() {
        push_empty_table(out, &RESULTS_HEADER, None);
        return;
    }
    out.push_str("<Table>\n");
    push_row(out, &RESULTS_HEADER);
    for scoped in results_in_reporting_order(results) {
        let status = scoped.result.status();
        let framework_id = scoped.framework_id.as_deref().unwrap_or("");
        let evidence_ids = scoped.result.evidence_refs().join(", ");
        push_row(
            out,
            &[
                framework_id,
                scoped.result.control_id(),
                scoped.result.rule_id(),
                status.label(),
                scoped.result.severity(),
                "",
                &evidence_ids,
                "",
                applicability_for(status),
            ],
        );
    }
    out.push_str("</Table>\n");
    push_autofilter(out, results.len() + 1, RESULTS_HEADER.len());
}

/// Appends the Gaps sheet's `<Table>` — the documented header row, then one
/// `<Row>` per compliance gap (a framework-scoped result that failed or warned and
/// so requires review) carrying a cell for each documented column: the composed
/// gap id (`framework:control:rule`), the framework, control, and rule ids that
/// trace it to the corpus, the catalogued control's own framework reference and
/// its framework's source URL, the severity, the gap type (the `FAIL`/`WARNING`
/// status label), the evidence ids, and an empty remediation. The populated table
/// is followed by an `<AutoFilter>` spanning its header row. A corpus with no
/// failing or warning framework-scoped result emits the documented header row and
/// an explanatory placeholder row, so the sheet stays present and says no potential
/// gap was observed.
fn push_gaps_table(
    out: &mut String,
    results: &[ScopedResult],
    controls: &[Control],
    frameworks: &[Framework],
) {
    let gaps: Vec<(&str, &ControlResult)> = results_in_reporting_order(results)
        .into_iter()
        .filter_map(gap_of)
        .collect();
    if gaps.is_empty() {
        push_empty_table(out, &GAPS_HEADER, Some(NO_GAPS_PLACEHOLDER));
        return;
    }
    let row_count = gaps.len() + 1;
    out.push_str("<Table>\n");
    push_row(out, &GAPS_HEADER);
    for (framework_id, result) in gaps {
        let gap_id = format!(
            "{framework_id}:{}:{}",
            result.control_id(),
            result.rule_id()
        );
        let reference = gap_reference(controls, framework_id, result.control_id());
        let source_url = framework_source_url(frameworks, framework_id);
        let evidence_ids = result.evidence_refs().join(", ");
        push_row(
            out,
            &[
                &gap_id,
                framework_id,
                result.control_id(),
                result.rule_id(),
                reference,
                source_url,
                result.severity(),
                result.status().label(),
                &evidence_ids,
                "",
            ],
        );
    }
    out.push_str("</Table>\n");
    push_autofilter(out, row_count, GAPS_HEADER.len());
}

/// Returns the framework a gap was found under and the result that records it,
/// when `scoped` is a compliance gap: a framework-scoped result whose status is
/// `FAIL` or `WARNING`. A passed, skipped, or errored result — or one carrying no
/// framework — is not a gap and yields `None`, so it never reaches the Gaps sheet.
fn gap_of(scoped: &ScopedResult) -> Option<(&str, &ControlResult)> {
    let framework_id = scoped.framework_id.as_deref()?;
    matches!(scoped.result.status(), Status::Fail | Status::Warning)
        .then_some((framework_id, &scoped.result))
}

/// The framework reference a gap on `control_id` under `framework_id` renders — the
/// catalogued control's own non-CWE reference, looked up by framework and control
/// id so each gap shows its own reference rather than a shared constant. A gap whose
/// control the corpus did not catalogue renders an empty reference, never a CWE
/// fallback.
fn gap_reference<'a>(controls: &'a [Control], framework_id: &str, control_id: &str) -> &'a str {
    controls
        .iter()
        .find(|control| control.framework_id == framework_id && control.id == control_id)
        .map_or("", |control| control.reference.as_str())
}

/// The source URL a gap under `framework_id` renders — the framework's own source
/// URL, looked up by id so the Gaps row reuses the framework the corpus already
/// holds instead of duplicating the URL. A gap whose framework the corpus does not
/// list renders an empty source URL.
fn framework_source_url<'a>(frameworks: &'a [Framework], framework_id: &str) -> &'a str {
    frameworks
        .iter()
        .find(|framework| framework.id == framework_id)
        .map_or("", |framework| framework.source_url.as_str())
}

/// Appends the Evidence sheet's `<Table>` — the documented header row, then one
/// `<Row>` per collected evidence record carrying a cell for each documented
/// column: the stable evidence id it is filed under, its kind, the location it was
/// collected from, an empty collector, its `sha256:…` integrity digest, and the
/// redaction status its classification yields. A classified record contributes
/// only this metadata — the store dropped its raw value, so no raw value reaches a
/// cell. A corpus with no evidence record emits the documented header row and an
/// explanatory placeholder row, so the sheet stays present and says no evidence
/// record was collected.
fn push_evidence_table(out: &mut String, evidence: &[Evidence]) {
    if evidence.is_empty() {
        push_empty_table(out, &EVIDENCE_HEADER, Some(NO_EVIDENCE_PLACEHOLDER));
        return;
    }
    out.push_str("<Table>\n");
    push_row(out, &EVIDENCE_HEADER);
    for record in evidence {
        let integrity = if record.integrity.is_empty() {
            INTEGRITY_UNAVAILABLE
        } else {
            record.integrity.as_str()
        };
        push_row(
            out,
            &[
                &record.id,
                &record.kind,
                &record.location,
                "",
                integrity,
                redaction_status(record.classification),
            ],
        );
    }
    out.push_str("</Table>\n");
}

/// Appends the Frameworks sheet's `<Table>` — the documented header row, then one
/// `<Row>` per framework with cells for its id, catalog version, and source URL.
/// An empty corpus emits the documented header row alone, so the sheet stays
/// present with its columns.
fn push_frameworks_table(out: &mut String, frameworks: &[Framework]) {
    if frameworks.is_empty() {
        push_empty_table(out, &FRAMEWORKS_HEADER, None);
        return;
    }
    out.push_str("<Table>\n");
    push_row(out, &FRAMEWORKS_HEADER);
    for framework in frameworks {
        push_row(
            out,
            &[&framework.id, &framework.version, &framework.source_url],
        );
    }
    out.push_str("</Table>\n");
}

/// Appends the Summary sheet's `<Table>` — the documented header row naming the
/// per-framework status tally, then that tally and the MAT-87 score scopes
/// (control, framework, environment) folded from the corpus's framework-scoped
/// results. The score-scope rows are labelled rows below the tally, not a second
/// tabular header. A corpus with no framework-scoped result emits the documented
/// header row and an explanatory placeholder row, so the sheet stays present and
/// says no scores are available for the run.
fn push_summary_table(out: &mut String, results: &[ScopedResult]) {
    let environment = environment_score(results);
    if environment.frameworks().is_empty() {
        let placeholder = if results.is_empty() {
            NO_CONTROLS_PLACEHOLDER
        } else {
            NO_SCORES_PLACEHOLDER
        };
        push_empty_table(out, &SUMMARY_HEADER, Some(placeholder));
        return;
    }
    out.push_str("<Table>\n");
    push_row(out, &SUMMARY_HEADER);
    for framework in environment.frameworks() {
        push_status_count_rows(out, framework);
    }
    for framework in environment.frameworks() {
        for control in framework.controls() {
            push_control_score_row(out, control);
        }
        push_framework_score_row(out, framework);
    }
    push_environment_score_row(out, &environment);
    if environment.incomplete() {
        push_scores_incomplete_row(out);
    }
    out.push_str("</Table>\n");
}

/// Folds the corpus's framework-scoped results into a MAT-87 environment score.
///
/// The results are grouped into a minimal catalog by the framework each was
/// evaluated under, then scored by the SDK; the exporter consumes the score and
/// never recomputes it. A result with no framework is left unmapped and excluded.
fn environment_score(results: &[ScopedResult]) -> EnvironmentScore {
    let catalog = scoring_catalog(results);
    let control_results: Vec<ControlResult> =
        results.iter().map(|scoped| scoped.result.clone()).collect();
    EnvironmentScore::compute(&catalog, &control_results)
}

/// Builds the minimal catalog the SDK needs to partition results by framework:
/// one framework, control, and mapping per distinct framework-scoped result, each
/// control carrying the severity and weight its result recorded.
fn scoring_catalog(results: &[ScopedResult]) -> Catalog {
    let mut frameworks: Vec<sovri_sdk::Framework> = Vec::new();
    let mut controls: Vec<sovri_sdk::Control> = Vec::new();
    let mut mappings: Vec<Mapping> = Vec::new();
    for scoped in results {
        let Some(framework_id) = scoped.framework_id.as_deref() else {
            continue;
        };
        let control_id = scoped.result.control_id();
        if !frameworks
            .iter()
            .any(|framework| framework.id() == framework_id)
        {
            frameworks.push(sovri_sdk::Framework::new(framework_id, ""));
        }
        if !controls.iter().any(|control| control.id() == control_id) {
            controls.push(sovri_sdk::Control::new(
                control_id,
                scoped.result.severity(),
                scoped.result.weight(),
                "",
            ));
        }
        if !mappings.iter().any(|mapping| {
            mapping.control_id() == control_id && mapping.framework_id() == framework_id
        }) {
            mappings.push(Mapping::new(control_id, framework_id));
        }
    }
    Catalog::new(frameworks, controls, Vec::new(), mappings)
}

/// Appends one status-tally `<Row>` per non-zero status for `framework` — its
/// framework id, the status label, and the count — in the fixed status order.
fn push_status_count_rows(out: &mut String, framework: &FrameworkScore) {
    let counts = framework.counts();
    for status in SUMMARY_STATUS_ORDER {
        let count = status_count(counts, status);
        if count > 0 {
            out.push_str("<Row>");
            push_string_cell(out, framework.framework_id());
            push_string_cell(out, status.label());
            push_string_cell(out, &count.to_string());
            out.push_str("</Row>\n");
        }
    }
}

/// The number of results `counts` tallied for `status`.
fn status_count(counts: StatusCounts, status: Status) -> u32 {
    match status {
        Status::Pass => counts.pass(),
        Status::Fail => counts.fail(),
        Status::Warning => counts.warning(),
        Status::Skipped => counts.skipped(),
        Status::Error => counts.error(),
    }
}

/// Appends the control-score `<Row>` naming the control scope — its label, the
/// scored control id, its rule id, and the result status the score folds.
fn push_control_score_row(out: &mut String, control: &ControlScore) {
    out.push_str("<Row>");
    push_string_cell(out, CONTROL_SCORE_LABEL);
    push_string_cell(out, control.control_id());
    push_string_cell(out, control.rule_id());
    push_string_cell(out, control.status().label());
    out.push_str("</Row>\n");
}

/// Appends the framework-score `<Row>` naming the framework scope — its label,
/// the framework id, and the score ratio the SDK derived.
fn push_framework_score_row(out: &mut String, framework: &FrameworkScore) {
    out.push_str("<Row>");
    push_string_cell(out, FRAMEWORK_SCORE_LABEL);
    push_string_cell(out, framework.framework_id());
    push_string_cell(out, &framework.ratio().to_string());
    out.push_str("</Row>\n");
}

/// Appends the environment-score `<Row>` naming the environment scope — its label
/// and the pooled score ratio the SDK derived across every framework.
fn push_environment_score_row(out: &mut String, environment: &EnvironmentScore) {
    out.push_str("<Row>");
    push_string_cell(out, ENVIRONMENT_SCORE_LABEL);
    push_string_cell(out, &environment.ratio().to_string());
    out.push_str("</Row>\n");
}

/// Appends the marker `<Row>` that flags the scores as incomplete because an
/// errored control was observed and excluded from them.
fn push_scores_incomplete_row(out: &mut String) {
    out.push_str("<Row>");
    push_string_cell(out, SCORES_INCOMPLETE_MARKER);
    out.push_str("</Row>\n");
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
