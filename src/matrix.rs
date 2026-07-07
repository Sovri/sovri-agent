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
/// generated date, the catalogued controls the Controls sheet lists, the control
/// results the Results sheet renders, the collected evidence the Evidence sheet
/// renders, and the frameworks the Frameworks sheet lists; later sheets read
/// their rows from the same corpus.
pub struct Corpus {
    executed_at: String,
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
/// results.
struct Control {
    framework_id: String,
    id: String,
    title: String,
    severity: String,
    weight: u32,
}

/// A collected evidence record the corpus holds, carrying the stable id it is
/// filed under and the location it was collected from.
///
/// The Evidence sheet lays out one row per record: its evidence id, so a Results
/// or Gaps row's evidence reference traces back to the record here, and the
/// location the evidence was collected at — a built asset, a config file, or
/// another artifact a finding was anchored to. The record is read from the
/// persisted store, never recollected here.
struct Evidence {
    id: String,
    location: String,
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
            controls: Vec::new(),
            results: Vec::new(),
            evidence: Vec::new(),
            frameworks: Vec::new(),
        }
    }

    /// Adds a catalogued control the corpus evaluated, rendered as one row on the
    /// Controls sheet.
    ///
    /// The Controls sheet lays out the catalogued fields that describe a control —
    /// the framework it belongs to, its stable id, its title, severity, and
    /// weight — as read from the persisted catalog, never recomputed here. The
    /// title is catalog metadata a control result does not carry, so the corpus
    /// records it here. The builder is chainable.
    #[must_use]
    pub fn with_control(
        mut self,
        framework_id: impl Into<String>,
        control_id: impl Into<String>,
        title: impl Into<String>,
        severity: impl Into<String>,
        weight: u32,
    ) -> Self {
        self.controls.push(Control {
            framework_id: framework_id.into(),
            id: control_id.into(),
            title: title.into(),
            severity: severity.into(),
            weight,
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
    /// The Evidence sheet lays out each record's stable evidence id — the id a
    /// Results or Gaps row references to trace a finding back to its evidence —
    /// and the location the evidence was collected from, as read from the
    /// persisted store and never recollected here. The builder is chainable.
    #[must_use]
    pub fn with_evidence(
        mut self,
        evidence_id: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        self.evidence.push(Evidence {
            id: evidence_id.into(),
            location: location.into(),
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
    let created = &corpus.executed_at;
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
            push_gaps_table(&mut worksheets, &corpus.results);
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

/// Appends the Controls sheet's `<Table>` — one `<Row>` per catalogued control,
/// each carrying the framework it belongs to, its control id, its catalogued
/// title, and its severity and weight. A corpus with no catalogued control keeps
/// the self-closing `<Table/>`, so no control absent from the corpus can appear.
fn push_controls_table(out: &mut String, controls: &[Control]) {
    if controls.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for control in controls {
        out.push_str("<Row>");
        push_string_cell(out, &control.framework_id);
        push_string_cell(out, &control.id);
        push_string_cell(out, &control.title);
        push_string_cell(out, &control.severity);
        push_string_cell(out, &control.weight.to_string());
        out.push_str("</Row>\n");
    }
    out.push_str("</Table>\n");
}

/// Appends the Results sheet's `<Table>` — one `<Row>` per control result,
/// carrying the ids that trace it to the corpus (control id, rule id), the
/// result's status label (`PASS`, `FAIL`, `WARNING`, `SKIPPED`, or `ERROR`), and
/// the evidence ids it references. An empty corpus keeps the self-closing
/// `<Table/>`, so the sheet stays present but carries no rows.
fn push_results_table(out: &mut String, results: &[ScopedResult]) {
    if results.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for scoped in results {
        out.push_str("<Row>");
        push_string_cell(out, scoped.result.control_id());
        push_string_cell(out, scoped.result.rule_id());
        push_string_cell(out, scoped.result.status().label());
        push_string_cell(out, &scoped.result.evidence_refs().join(", "));
        out.push_str("</Row>\n");
    }
    out.push_str("</Table>\n");
}

/// Appends the Gaps sheet's `<Table>` — one `<Row>` per compliance gap, a
/// framework-scoped result that failed or warned and so requires review. Each row
/// carries the composed gap id (`framework:control:rule`) and the framework,
/// control, rule, and evidence ids that trace the gap back to the corpus. A
/// corpus with no failing or warning framework-scoped result keeps the
/// self-closing `<Table/>`, so the sheet stays present but carries no rows.
fn push_gaps_table(out: &mut String, results: &[ScopedResult]) {
    let gaps: Vec<(&str, &ControlResult)> = results.iter().filter_map(gap_of).collect();
    if gaps.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for (framework_id, result) in gaps {
        let gap_id = format!(
            "{framework_id}:{}:{}",
            result.control_id(),
            result.rule_id()
        );
        out.push_str("<Row>");
        push_string_cell(out, &gap_id);
        push_string_cell(out, framework_id);
        push_string_cell(out, result.control_id());
        push_string_cell(out, result.rule_id());
        push_string_cell(out, &result.evidence_refs().join(", "));
        out.push_str("</Row>\n");
    }
    out.push_str("</Table>\n");
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

/// Appends the Evidence sheet's `<Table>` — one `<Row>` per collected evidence
/// record, carrying the stable evidence id it is filed under and the location it
/// was collected from. A corpus with no evidence record keeps the self-closing
/// `<Table/>`, so the sheet stays present but carries no rows.
fn push_evidence_table(out: &mut String, evidence: &[Evidence]) {
    if evidence.is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
    for record in evidence {
        out.push_str("<Row>");
        push_string_cell(out, &record.id);
        push_string_cell(out, &record.location);
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

/// Appends the Summary sheet's `<Table>` — the per-framework status tally and the
/// MAT-87 score scopes (control, framework, environment) folded from the corpus's
/// framework-scoped results. A corpus with no framework-scoped result keeps the
/// self-closing `<Table/>`, so the sheet stays present but carries no rows.
fn push_summary_table(out: &mut String, results: &[ScopedResult]) {
    let environment = environment_score(results);
    if environment.frameworks().is_empty() {
        out.push_str("<Table/>\n");
        return;
    }
    out.push_str("<Table>\n");
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
