// Copyright 2026 Sovri contributors
// SPDX-License-Identifier: Apache-2.0

//! The `sovri-agent scan` command: run a catalog's controls against the host
//! scanners and report the outcome.
//!
//! The pipeline is a straight line: parse the flags, load the `--catalog`
//! directory, validate it, resolve the `--framework`/`--control` selection, build
//! the host registry from the V0.4 scanners, execute the selected controls on the
//! SDK engine, render the listing plus the compliance gaps, and map the result
//! statuses to an exit code. Every error surface before host acquisition
//! (parse / load / validate / resolve) resolves without reading the machine, so
//! those paths are host-independent.
//!
//! The exit-code contract (R-05): `0` when the run is clean, `2` on a posture
//! breach (a FAIL, an execution ERROR, or a WARNING under `--fail-on=warning`),
//! and `64` on a usage, catalog-load, or validation error. The report carries no
//! wall-clock value, so a fixed host state renders byte-identically across runs
//! (R-06).
//!
//! The item names `run_scan`, `ScanOutcome`, and `ScanError` repeat the module
//! name. They are the MAT-125 acceptance contract the tests import, so the
//! repetition is accepted here as it is in the sibling scanner modules.
#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::process::ExitCode;
use std::sync::Arc;

use sovri_sdk::{
    collect_gaps, Catalog, ControlResult, Engine, ExecutionError, LoadError, RuleEvaluator,
    Selection, Status, ValidationIssue,
};

use crate::scanners::docker::{
    DockerPolicy, DockerScanner, HardeningOption, DAEMON_VERSION_EOL_RULE,
};
use crate::scanners::ssh::{SshPolicy, SshScanner, PASSWORD_AUTH_RULE, PERMIT_ROOT_LOGIN_RULE};
use crate::scanners::system::{
    ServicePolicy, SupportPolicy, SystemPolicy, SystemScanner, OS_EOL_RULE,
};
use crate::scanners::user::{UserPolicy, UserScanner, SINGLE_ROOT_RULE};
use crate::scanners::{AcquireError, Registry};

/// Exit code when the scan completed and no threshold was breached.
const EXIT_CLEAN: u8 = 0;
/// Exit code when the posture threshold was breached: a FAIL, an execution
/// ERROR, or a WARNING under `--fail-on=warning`.
const EXIT_POSTURE_BREACH: u8 = 2;
/// Exit code for a usage, catalog-load, or catalog-validation error.
const EXIT_USAGE: u8 = 64;

/// Execution metadata every result carries. It is never printed, so it does not
/// affect the byte-for-byte reproducibility of the report (R-06).
const EXECUTION_METADATA: &str = "engine=sovri-agent";

/// The execution timestamp the CLI stamps onto results. It is a fixed,
/// timezone-qualified ISO-8601 constant, never the wall clock: the value is not
/// printed and reading the clock would break the offline (R-07) and deterministic
/// (R-06) guarantees. Real timestamping is future work.
const SCAN_EXECUTED_AT: &str = "2000-01-01T00:00:00Z";

/// A dormancy threshold, in days, for the baseline user policy (MAT-124 sources
/// the real CIS baselines).
const BASELINE_INACTIVITY_DAYS: u32 = 90;
/// The baseline minimum-supported Docker daemon version (MAT-124 placeholder).
const BASELINE_DOCKER_MIN_SUPPORTED: &str = "24.0";
/// The baseline minimum-recommended Docker daemon version (MAT-124 placeholder).
const BASELINE_DOCKER_MIN_RECOMMENDED: &str = "27.0";

/// The `--help` text. It documents the exit codes so the contract is discoverable
/// from the command line (R-05).
const HELP: &str = "\
usage: sovri-agent scan --catalog <dir> (--framework <id> | --control <ids>) [--fail-on <level>]

Run a catalog's controls against the host and report the outcome.

options:
  --catalog <dir>     directory of framework/control/rule/mapping YAML (required)
  --framework <id>    run every control mapped to this framework
  --control <ids>     run these comma-separated control ids
  --fail-on <level>   posture threshold: fail (default), warning, or never
  -h, --help          show this help

exit codes:
  0 when clean, 2 on a FAIL or execution error, 64 on a usage error
";

/// The result status at which the scan treats the run as a posture breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    /// Breach on any FAIL (the default).
    Fail,
    /// Breach on any FAIL or WARNING.
    Warning,
    /// Never breach on posture; always exit clean.
    Never,
}

impl FailOn {
    /// Parses a `--fail-on` value.
    ///
    /// # Errors
    /// Returns [`ScanError::InvalidFailOn`] for any value other than `fail`,
    /// `warning`, or `never`.
    pub fn parse(raw: &str) -> Result<Self, ScanError> {
        match raw {
            "fail" => Ok(Self::Fail),
            "warning" => Ok(Self::Warning),
            "never" => Ok(Self::Never),
            other => Err(ScanError::InvalidFailOn(other.to_string())),
        }
    }
}

/// The exit code a set of result statuses maps to under `fail_on`.
///
/// [`FailOn::Never`] always yields the clean code. Otherwise any FAIL or any
/// ERROR is a breach, and under [`FailOn::Warning`] a WARNING is too. SKIPPED and
/// PASS never raise the posture (R-04).
#[must_use]
pub fn posture_exit_code(statuses: &[Status], fail_on: FailOn) -> u8 {
    if matches!(fail_on, FailOn::Never) {
        return EXIT_CLEAN;
    }
    let breach = statuses.iter().any(|status| match status {
        Status::Fail | Status::Error => true,
        Status::Warning => matches!(fail_on, FailOn::Warning),
        Status::Pass | Status::Skipped => false,
    });
    if breach {
        EXIT_POSTURE_BREACH
    } else {
        EXIT_CLEAN
    }
}

/// Renders the control-result listing and the compliance-gaps section.
///
/// The listing prints one line per result — control id, rule id, status label,
/// reason, then any evidence references in brackets — in the order the engine
/// returned them (control id, then rule id). A result with no evidence renders
/// its line without a bracket. An empty result set renders a single explanatory
/// line. No execution timestamp or other wall-clock value is printed, so the
/// output is byte-identical across runs of the same host state (R-06). The gaps
/// section projects the FAIL and WARNING results through [`collect_gaps`]; PASS,
/// SKIPPED, and ERROR are not gaps (R-03).
#[must_use]
pub fn render_report(results: &[ControlResult], catalog: &Catalog) -> String {
    let mut out = String::new();

    if results.is_empty() {
        out.push_str("No controls were executed.\n");
    } else {
        for result in results {
            let reason = result
                .reason()
                .unwrap_or_else(|| result.status().description());
            out.push_str(result.control_id());
            out.push_str("  ");
            out.push_str(result.rule_id());
            out.push_str("  ");
            out.push_str(result.status().label());
            out.push_str("  ");
            out.push_str(reason);
            let refs = result.evidence_refs();
            if !refs.is_empty() {
                out.push_str("  [");
                out.push_str(&refs.join(", "));
                out.push(']');
            }
            out.push('\n');
        }
    }

    out.push_str("\nCompliance gaps\n");
    let gaps = collect_gaps(catalog, results);
    if gaps.is_empty() {
        out.push_str("No compliance gaps were found.\n");
    } else {
        for gap in &gaps {
            out.push_str(gap.control_id());
            out.push_str("  ");
            out.push_str(gap.reason());
            out.push('\n');
            let remediation = gap.remediation();
            if !remediation.is_empty() {
                out.push_str("    remediation: ");
                out.push_str(remediation);
                out.push('\n');
            }
        }
    }

    out
}

/// Resolves the `--framework` / `--control` flags into a [`Selection`].
///
/// Exactly one of the two must be given. Control ids are split on commas, each is
/// checked against the catalog, and duplicates are dropped preserving first-seen
/// order — a repeated id runs its control once, it is not an error.
///
/// # Errors
/// Returns [`ScanError::NoSelection`] or [`ScanError::BothSelectionModes`] when
/// the count of flags is not exactly one; [`ScanError::UnknownFramework`] or
/// [`ScanError::UnknownControl`] when an id is not in the catalog; and
/// [`ScanError::EmptyControlId`] when a control entry is empty.
pub fn resolve_selection(
    catalog: &Catalog,
    framework: Option<&str>,
    control: Option<&str>,
) -> Result<Selection, ScanError> {
    match (framework, control) {
        (Some(_), Some(_)) => Err(ScanError::BothSelectionModes),
        (None, None) => Err(ScanError::NoSelection),
        (Some(framework_id), None) => {
            if catalog.framework(framework_id).is_none() {
                return Err(ScanError::UnknownFramework(framework_id.to_string()));
            }
            Ok(Selection::framework(framework_id))
        }
        (None, Some(control_list)) => {
            let mut ids: Vec<String> = Vec::new();
            for entry in control_list.split(',') {
                if entry.is_empty() {
                    return Err(ScanError::EmptyControlId);
                }
                if catalog.control(entry).is_none() {
                    return Err(ScanError::UnknownControl(entry.to_string()));
                }
                if !ids.iter().any(|seen| seen == entry) {
                    ids.push(entry.to_string());
                }
            }
            Ok(Selection::controls(ids))
        }
    }
}

/// The outcome of a scan: the rendered report, the raw results, and the exit code.
pub struct ScanOutcome {
    report: String,
    results: Vec<ControlResult>,
    exit_code: u8,
}

impl ScanOutcome {
    /// The rendered report: the control listing followed by the compliance gaps.
    #[must_use]
    pub fn report(&self) -> &str {
        &self.report
    }

    /// The control results, in reporting order (control id, then rule id).
    #[must_use]
    pub fn results(&self) -> &[ControlResult] {
        &self.results
    }

    /// The exit code the run maps to under the caller's threshold.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

/// Runs the selected controls on the engine and returns the report, results, and
/// exit code.
///
/// The engine turns an evaluator failure into an ERROR result rather than
/// aborting, so a scan over registered scanners completes; the only error this
/// returns is the unknown-control backstop.
///
/// # Errors
/// Returns [`ScanError::UnknownControl`] when the selection names a control the
/// catalog does not define. [`resolve_selection`] rules that out first, so this
/// is a backstop for callers that build a [`Selection`] directly.
pub fn run_scan<E: RuleEvaluator>(
    catalog: &Catalog,
    selection: &Selection,
    evaluator: &E,
    fail_on: FailOn,
    executed_at: &str,
) -> Result<ScanOutcome, ScanError> {
    let engine =
        Engine::new(executed_at, EXECUTION_METADATA).map_err(|_| ScanError::InvalidTimestamp)?;
    let results = engine.execute(catalog, selection, evaluator)?;
    let report = render_report(&results, catalog);
    let statuses: Vec<Status> = results.iter().map(ControlResult::status).collect();
    let exit_code = posture_exit_code(&statuses, fail_on);
    Ok(ScanOutcome {
        report,
        results,
        exit_code,
    })
}

/// Runs `sovri-agent scan` from the arguments after the `scan` subcommand and
/// returns the process exit code.
///
/// On success the report is printed to standard output; every error is printed to
/// standard error, so a failed run prints no control listing.
#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let config = match parse_args(args) {
        Ok(ParsedArgs::Help) => {
            print!("{HELP}");
            return ExitCode::from(EXIT_CLEAN);
        }
        Ok(ParsedArgs::Scan(config)) => config,
        Err(error) => return fail(&error),
    };
    match execute(&config) {
        Ok(outcome) => {
            print!("{}", outcome.report());
            ExitCode::from(outcome.exit_code())
        }
        Err(error) => fail(&error),
    }
}

/// Prints `error` to standard error and returns its exit code.
fn fail(error: &ScanError) -> ExitCode {
    eprintln!("sovri-agent scan: {error}");
    ExitCode::from(error.exit_code())
}

/// Loads and validates the catalog, resolves the selection, builds the host
/// registry, and runs the scan.
fn execute(config: &ScanConfig) -> Result<ScanOutcome, ScanError> {
    let catalog = Catalog::load_from_dir(&config.catalog).map_err(ScanError::CatalogLoad)?;
    catalog.validate().map_err(ScanError::CatalogInvalid)?;
    let selection = resolve_selection(
        &catalog,
        config.framework.as_deref(),
        config.control.as_deref(),
    )?;
    let registry = host_registry()?;
    run_scan(
        &catalog,
        &selection,
        &registry,
        config.fail_on,
        SCAN_EXECUTED_AT,
    )
}

/// Builds the host registry: acquire each V0.4 scanner from the host under the
/// agent's baseline policies and register it for its rule id(s). The SSH scanner
/// backs two rules, so it is shared through one `Arc`.
///
/// The baseline policies are placeholders; sourcing the real CIS baselines is
/// MAT-124. Docker and SSH acquisition are infallible; a System or User
/// acquisition failure aborts the scan with [`ScanError::HostAcquire`].
fn host_registry() -> Result<Registry, ScanError> {
    let mut registry = Registry::new();

    let system =
        SystemScanner::acquire(baseline_system_policy()).map_err(ScanError::HostAcquire)?;
    registry.register_rule_evaluator(OS_EOL_RULE, Arc::new(system));

    let user = UserScanner::acquire(baseline_user_policy()).map_err(ScanError::HostAcquire)?;
    registry.register_rule_evaluator(SINGLE_ROOT_RULE, Arc::new(user));

    let docker = DockerScanner::acquire(baseline_docker_policy());
    registry.register_rule_evaluator(DAEMON_VERSION_EOL_RULE, Arc::new(docker));

    let ssh: Arc<dyn RuleEvaluator + Send + Sync> =
        Arc::new(SshScanner::acquire(baseline_ssh_policy()));
    registry.register_rule_evaluator(PERMIT_ROOT_LOGIN_RULE, Arc::clone(&ssh));
    registry.register_rule_evaluator(PASSWORD_AUTH_RULE, ssh);

    Ok(registry)
}

/// The baseline system policy: no support table and no interdicted services
/// (MAT-124 placeholder).
fn baseline_system_policy() -> SystemPolicy {
    SystemPolicy::new(
        SupportPolicy::new(),
        ServicePolicy::interdicting(Vec::<&str>::new()),
    )
}

/// The baseline user policy: a 90-day dormancy threshold, root expected
/// privileged (MAT-124 placeholder).
fn baseline_user_policy() -> UserPolicy {
    UserPolicy::new(BASELINE_INACTIVITY_DAYS, ["root"])
}

/// The baseline Docker policy (MAT-124 placeholder).
fn baseline_docker_policy() -> DockerPolicy {
    DockerPolicy::new(
        BASELINE_DOCKER_MIN_SUPPORTED,
        BASELINE_DOCKER_MIN_RECOMMENDED,
        Vec::<HardeningOption>::new(),
    )
}

/// The baseline SSH policy: no weak-crypto lists, so only the root-login and
/// password-auth rules are assessed (MAT-124 placeholder).
fn baseline_ssh_policy() -> SshPolicy {
    SshPolicy::new(Vec::<&str>::new(), Vec::<&str>::new(), Vec::<&str>::new())
}

/// The parsed scan configuration.
struct ScanConfig {
    catalog: String,
    framework: Option<String>,
    control: Option<String>,
    fail_on: FailOn,
}

/// The two shapes of a parsed command line: a help request or a scan to run.
enum ParsedArgs {
    Help,
    Scan(ScanConfig),
}

/// Parses the scan arguments into a [`ScanConfig`], or a help request.
fn parse_args(args: &[String]) -> Result<ParsedArgs, ScanError> {
    let mut catalog: Option<String> = None;
    let mut framework: Option<String> = None;
    let mut control: Option<String> = None;
    let mut fail_on = FailOn::Fail;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(ParsedArgs::Help);
        } else if let Some(value) = arg.strip_prefix("--catalog=") {
            catalog = Some(value.to_string());
        } else if arg == "--catalog" {
            catalog = Some(next_value(&mut iter, "--catalog")?);
        } else if let Some(value) = arg.strip_prefix("--framework=") {
            framework = Some(value.to_string());
        } else if arg == "--framework" {
            framework = Some(next_value(&mut iter, "--framework")?);
        } else if let Some(value) = arg.strip_prefix("--control=") {
            control = Some(value.to_string());
        } else if arg == "--control" {
            control = Some(next_value(&mut iter, "--control")?);
        } else if let Some(value) = arg.strip_prefix("--fail-on=") {
            fail_on = FailOn::parse(value)?;
        } else if arg == "--fail-on" {
            fail_on = FailOn::parse(&next_value(&mut iter, "--fail-on")?)?;
        } else {
            return Err(ScanError::UnknownArgument(arg.clone()));
        }
    }

    let catalog = catalog.ok_or(ScanError::MissingCatalog)?;
    Ok(ParsedArgs::Scan(ScanConfig {
        catalog,
        framework,
        control,
        fail_on,
    }))
}

/// The value following a `flag` that takes one, or a [`ScanError::MissingValue`].
fn next_value(iter: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, ScanError> {
    iter.next()
        .cloned()
        .ok_or_else(|| ScanError::MissingValue(flag.to_string()))
}

/// Why a scan could not run to completion.
#[derive(Debug)]
pub enum ScanError {
    /// Neither `--framework` nor `--control` was given.
    NoSelection,
    /// Both `--framework` and `--control` were given.
    BothSelectionModes,
    /// The requested framework is not in the catalog.
    UnknownFramework(String),
    /// A requested control is not in the catalog.
    UnknownControl(String),
    /// A control-id entry in the selection was empty.
    EmptyControlId,
    /// The `--fail-on` value was not `fail`, `warning`, or `never`.
    InvalidFailOn(String),
    /// An argument was not recognized.
    UnknownArgument(String),
    /// A flag that takes a value was given none.
    MissingValue(String),
    /// The required `--catalog` option was not given.
    MissingCatalog,
    /// The execution timestamp was not a timezone-qualified ISO-8601 value.
    InvalidTimestamp,
    /// The catalog directory could not be loaded.
    CatalogLoad(LoadError),
    /// The catalog loaded but failed validation.
    CatalogInvalid(ValidationIssue),
    /// Host state could not be acquired for a scanner.
    HostAcquire(AcquireError),
}

impl ScanError {
    /// The process exit code this error maps to: `64` for a usage, load, or
    /// validation error, and `2` for a host-acquisition failure (an execution
    /// error).
    fn exit_code(&self) -> u8 {
        match self {
            Self::HostAcquire(_) => EXIT_POSTURE_BREACH,
            _ => EXIT_USAGE,
        }
    }
}

impl From<ExecutionError> for ScanError {
    fn from(error: ExecutionError) -> Self {
        match error {
            ExecutionError::UnknownControl { control_id } => Self::UnknownControl(control_id),
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSelection => f.write_str("exactly one of --framework or --control is required"),
            Self::BothSelectionModes => {
                f.write_str("--framework and --control are mutually exclusive")
            }
            Self::UnknownFramework(id) => write!(f, "unknown framework \"{id}\""),
            Self::UnknownControl(id) => write!(f, "unknown control \"{id}\""),
            Self::EmptyControlId => f.write_str("empty control id in the selection"),
            Self::InvalidFailOn(value) => write!(f, "invalid --fail-on value \"{value}\""),
            Self::UnknownArgument(arg) => write!(f, "unknown argument \"{arg}\""),
            Self::MissingValue(flag) => write!(f, "the {flag} option needs a value"),
            Self::MissingCatalog => f.write_str("the --catalog <dir> option is required"),
            Self::InvalidTimestamp => {
                f.write_str("the execution timestamp is not a timezone-qualified ISO-8601 value")
            }
            Self::CatalogLoad(error) => write!(f, "the catalog could not be loaded: {error}"),
            Self::CatalogInvalid(issue) => write!(f, "the catalog is invalid: {issue}"),
            Self::HostAcquire(error) => write!(f, "host state could not be acquired: {error}"),
        }
    }
}

impl std::error::Error for ScanError {}
