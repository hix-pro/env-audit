use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::analyze::{self, Audit};
use crate::declarations;
use crate::model::FindingKind;
use crate::report::{self, TextOptions};
use crate::scan;

#[derive(Debug, Parser)]
#[command(
    name = "envaudit",
    version,
    about = "Audit environment variable usage, documentation, and secrets in a repository.",
    long_about = "EnvAudit is a local-first CLI that finds environment variables a repository uses \
                  but never documents, documents but never uses, and secret-looking values that \
                  should not be committed.",
    after_help = "Examples:\n  envaudit scan\n  envaudit scan ./service --json\n  envaudit scan . --fail-on missing\n\nExit codes:\n  0  success or report-only run with findings\n  1  usage, I/O, or parse error\n  2  findings matched --fail-on"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a project directory for environment variable issues.
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Directory to scan (defaults to the current directory).
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit a stable JSON document.
    #[arg(long, conflicts_with = "markdown")]
    json: bool,

    /// Emit a Markdown report.
    #[arg(long)]
    markdown: bool,

    /// Emit a SARIF 2.1.0 report for GitHub code scanning.
    #[arg(long, conflicts_with_all = ["json", "markdown"])]
    sarif: bool,

    /// Exit with code 2 when matching findings are present.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Fail on any non-informational finding.
    Any,
    /// Fail only when an undeclared variable is used.
    Missing,
    /// Fail only when a likely secret is detected.
    Secret,
}

impl FailOn {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Missing => "missing",
            Self::Secret => "secret",
        }
    }
}

/// Parses arguments, runs the scan, renders output, and returns the process
/// exit code.
pub fn run() -> Result<u8> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let display_only = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            if let Err(print_error) = error.print() {
                if is_early_reader_exit(&print_error) {
                    // The reader went away (`envaudit --help | head -1`);
                    // treat it as normal termination.
                    return Ok(0);
                }
                return Err(print_error).context("failed to print help");
            }
            return Ok(if display_only { 0 } else { 1 });
        }
    };

    let Command::Scan(args) = cli.command;
    let collected = scan::collect(&args.path)?;
    let declarations = declarations::collect(&collected)?;
    let audit = analyze::analyze(&collected, &declarations);
    let failing = args
        .fail_on
        .is_some_and(|threshold| threshold_met(&audit, threshold));

    let output = if args.json {
        report::render_json(&audit)?
    } else if args.markdown {
        report::render_markdown(&audit)
    } else if args.sarif {
        report::render_sarif(&audit)?
    } else {
        report::render_text(
            &audit,
            TextOptions {
                color: report::color_enabled(),
                fail_on: args.fail_on.map(FailOn::as_str),
                failing,
            },
        )
    };

    write_stdout(&output)?;
    Ok(if failing { 2 } else { 0 })
}

pub fn threshold_met(audit: &Audit, threshold: FailOn) -> bool {
    match threshold {
        FailOn::Any => audit
            .findings
            .iter()
            .any(|finding| finding.severity != crate::model::Severity::Info),
        FailOn::Missing => audit
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Missing),
        FailOn::Secret => audit
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Secret),
    }
}

fn write_stdout(output: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(output.as_bytes()) {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(error).context("failed to write output");
    }
    stdout.flush().context("failed to flush output")?;
    Ok(())
}

/// Whether an I/O error while printing help, version, or usage means the
/// consumer left early (`envaudit --help | head -1`) rather than something
/// actually going wrong.
fn is_early_reader_exit(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Location, Severity};

    fn audit(kind: FindingKind, severity: Severity) -> Audit {
        Audit {
            root_display: ".".to_owned(),
            files_scanned: 1,
            findings: vec![Finding::new(
                kind,
                severity,
                "VAR",
                "summary",
                "fix",
                vec![Location::usage("src/app.ts", 1)],
            )],
        }
    }

    #[test]
    fn thresholds_match_the_expected_kinds() {
        let missing = audit(FindingKind::Missing, Severity::Error);
        assert!(threshold_met(&missing, FailOn::Any));
        assert!(threshold_met(&missing, FailOn::Missing));
        assert!(!threshold_met(&missing, FailOn::Secret));

        let secret = audit(FindingKind::Secret, Severity::Warning);
        assert!(threshold_met(&secret, FailOn::Any));
        assert!(!threshold_met(&secret, FailOn::Missing));
        assert!(threshold_met(&secret, FailOn::Secret));
    }

    #[test]
    fn any_ignores_information_findings() {
        let info = audit(FindingKind::Duplicate, Severity::Info);
        assert!(!threshold_met(&info, FailOn::Any));
    }

    #[test]
    fn clap_rejects_conflicting_output_flags() {
        let error = Cli::try_parse_from(["envaudit", "scan", "--json", "--markdown"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);

        let sarif = Cli::try_parse_from(["envaudit", "scan", "--sarif", "--json"]).unwrap_err();
        assert_eq!(sarif.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn closed_pipe_and_interrupted_prints_are_normal_termination() {
        assert!(is_early_reader_exit(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        )));
        assert!(is_early_reader_exit(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(!is_early_reader_exit(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }
}
