use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::IsTerminal;

use anyhow::Result;
use serde::Serialize;

use crate::analyze::Audit;
use crate::model::{Finding, FindingKind, Location, Role, Severity};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    tool: ToolInfo,
    root: &'a str,
    files_scanned: usize,
    summary: Summary,
    findings: &'a [Finding],
}

#[derive(Debug, Clone, Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    error: usize,
    warning: usize,
    info: usize,
    kinds: KindCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
struct KindCounts {
    missing: usize,
    unused: usize,
    undocumented: usize,
    secret: usize,
    duplicate: usize,
}

impl Summary {
    fn from_audit(audit: &Audit) -> Self {
        let mut kinds = KindCounts::default();
        for finding in &audit.findings {
            match finding.kind {
                FindingKind::Missing => kinds.missing += 1,
                FindingKind::Unused => kinds.unused += 1,
                FindingKind::Undocumented => kinds.undocumented += 1,
                FindingKind::Secret => kinds.secret += 1,
                FindingKind::Duplicate => kinds.duplicate += 1,
            }
        }
        Self {
            total: audit.findings.len(),
            critical: count_severity(audit, Severity::Critical),
            error: count_severity(audit, Severity::Error),
            warning: count_severity(audit, Severity::Warning),
            info: count_severity(audit, Severity::Info),
            kinds,
        }
    }
}

fn count_severity(audit: &Audit, severity: Severity) -> usize {
    audit
        .findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}

#[derive(Debug, Clone, Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: &'static str,
    short_description: SarifText,
    help_uri: &'static str,
    default_configuration: SarifLevel,
}

#[derive(Debug, Clone, Serialize)]
struct SarifText {
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct SarifLevel {
    level: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    rule_index: usize,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
}

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_HELP_URI: &str = "https://github.com/hix-pro/env-audit#what-is-detected";

const SARIF_RULES: [(FindingKind, &str, &str, &str); 5] = [
    (
        FindingKind::Missing,
        "MissingEnvironmentVariable",
        "An environment variable is used but never declared.",
        "error",
    ),
    (
        FindingKind::Unused,
        "UnusedEnvironmentVariable",
        "An environment variable is declared but never used.",
        "warning",
    ),
    (
        FindingKind::Undocumented,
        "UndocumentedEnvironmentVariable",
        "An environment variable is used but missing from the example file.",
        "warning",
    ),
    (
        FindingKind::Secret,
        "CommittedSecret",
        "A likely secret value is stored in a committed environment file.",
        "error",
    ),
    (
        FindingKind::Duplicate,
        "DuplicateEnvironmentVariable",
        "An environment variable is declared in more than one file.",
        "note",
    ),
];

fn sarif_rule_index(kind: FindingKind) -> usize {
    SARIF_RULES
        .iter()
        .position(|(rule_kind, ..)| *rule_kind == kind)
        .unwrap_or(0)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// SARIF artifact URIs must be relative to the repository root, use forward
/// slashes, and include the scanned subdirectory when the scan did not start
/// at the repository root.
fn sarif_uri(root: &str, path: &str) -> String {
    let path = path.replace('\\', "/");
    let path = path.strip_prefix("./").unwrap_or(&path);
    let root = root.replace('\\', "/");
    let root = root.trim_end_matches('/');
    let root = root.strip_prefix("./").unwrap_or(root);
    if root.is_empty() || root == "." || path.starts_with('/') || root.starts_with('/') {
        path.to_owned()
    } else {
        format!("{root}/{path}")
    }
}

/// SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.
pub fn render_sarif(audit: &Audit) -> Result<String> {
    let rules = SARIF_RULES
        .iter()
        .map(|(kind, name, description, level)| SarifRule {
            id: format!("envaudit/{}", kind.as_str()),
            name,
            short_description: SarifText {
                text: (*description).to_owned(),
            },
            help_uri: SARIF_HELP_URI,
            default_configuration: SarifLevel { level },
        })
        .collect();

    let results = audit
        .findings
        .iter()
        .map(|finding| SarifResult {
            rule_id: format!("envaudit/{}", finding.kind.as_str()),
            rule_index: sarif_rule_index(finding.kind),
            level: sarif_level(finding.severity),
            message: SarifText {
                text: format!(
                    "{}: {}\n\nFix: {}",
                    finding.variable, finding.summary, finding.fix
                ),
            },
            locations: finding
                .locations
                .iter()
                .map(|location| SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: sarif_uri(&audit.root_display, &location.path),
                        },
                        region: location.line.map(|line| SarifRegion {
                            start_line: line.max(1),
                        }),
                    },
                })
                .collect(),
        })
        .collect();

    let report = SarifLog {
        schema: SARIF_SCHEMA,
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "EnvAudit",
                    information_uri: "https://github.com/hix-pro/env-audit",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };

    let mut rendered = serde_json::to_string_pretty(&report)?;
    rendered.push('\n');
    Ok(rendered)
}

/// Stable JSON output. See the README for the documented schema.
pub fn render_json(audit: &Audit) -> Result<String> {
    let report = JsonReport {
        schema_version: SCHEMA_VERSION,
        tool: ToolInfo {
            name: "envaudit",
            version: env!("CARGO_PKG_VERSION"),
        },
        root: &audit.root_display,
        files_scanned: audit.files_scanned,
        summary: Summary::from_audit(audit),
        findings: &audit.findings,
    };
    let mut rendered = serde_json::to_string_pretty(&report)?;
    rendered.push('\n');
    Ok(rendered)
}

/// Stable Markdown output, grouped by severity.
pub fn render_markdown(audit: &Audit) -> String {
    let summary = Summary::from_audit(audit);
    let mut out = String::new();
    out.push_str("# EnvAudit report\n\n");
    let _ = writeln!(
        out,
        "Scanned {} files under {}. Secret values are never included in this report.\n",
        audit.files_scanned,
        inline_code(&audit.root_display)
    );

    out.push_str("## Summary\n\n");
    out.push_str("| Severity | Count |\n| --- | ---: |\n");
    for severity in Severity::ALL {
        let count = match severity {
            Severity::Critical => summary.critical,
            Severity::Error => summary.error,
            Severity::Warning => summary.warning,
            Severity::Info => summary.info,
        };
        let _ = writeln!(out, "| {} | {} |", capitalize(severity.label()), count);
    }
    let _ = writeln!(out, "| **Total** | **{}** |\n", summary.total);

    if audit.findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }

    for severity in Severity::ALL {
        let group: Vec<&Finding> = audit
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "## {} ({})\n",
            capitalize(severity.label()),
            group.len()
        );
        for finding in group {
            let _ = writeln!(
                out,
                "### {} — {}\n",
                inline_code(&finding.variable),
                finding.kind.as_str()
            );
            push_markdown_locations(&mut out, &finding.locations);
            let _ = writeln!(out, "- {}", finding.summary);
            let _ = writeln!(out, "- **Fix:** {}\n", finding.fix);
        }
    }

    out
}

fn push_markdown_locations(out: &mut String, locations: &[Location]) {
    let rendered: Vec<String> = locations.iter().map(format_location_markdown).collect();
    let _ = writeln!(out, "- **Locations:** {}", rendered.join(", "));
}

fn format_location_markdown(location: &Location) -> String {
    match location.line {
        Some(line) => inline_code(&format!("{}:{}", location.path, line)),
        None => inline_code(&location.path),
    }
}

fn inline_code(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            '`' => '\'',
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .collect();
    format!("`{sanitized}`")
}

#[derive(Debug, Clone, Copy)]
pub struct TextOptions<'a> {
    pub color: bool,
    pub fail_on: Option<&'a str>,
    pub failing: bool,
}

/// Human-readable output grouped by severity.
pub fn render_text(audit: &Audit, options: TextOptions<'_>) -> String {
    let style = Style::new(options.color);
    let summary = Summary::from_audit(audit);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}{} {}",
        style.bold("EnvAudit"),
        style.dim(" ·"),
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        out,
        "Scanned {} files under {}\n",
        audit.files_scanned,
        style.dim(&audit.root_display)
    );

    if audit.findings.is_empty() {
        out.push_str("No findings. Environment usage and documentation are consistent.\n");
    } else {
        for severity in Severity::ALL {
            let group: Vec<&Finding> = audit
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect();
            if group.is_empty() {
                continue;
            }
            let heading = format!("{} ({})", severity.label(), group.len());
            let _ = writeln!(out, "{}", style.severity(severity, &heading));
            for finding in group {
                push_text_finding(&mut out, finding, &style);
            }
            out.push('\n');
        }
    }

    let summary_line = format_summary(&summary);
    let _ = writeln!(out, "{}", style.bold(&summary_line));
    let result = match options.fail_on {
        None => "Result: report only (use --fail-on any|missing|secret to gate CI)".to_owned(),
        Some(threshold) if options.failing => {
            format!("Result: fail (--fail-on {threshold} matched findings)")
        }
        Some(threshold) => {
            format!("Result: pass (--fail-on {threshold} found no matching findings)")
        }
    };
    let _ = writeln!(out, "{result}");

    out
}

fn push_text_finding(out: &mut String, finding: &Finding, style: &Style) {
    // Pad the plain kind name before styling it: a `{:<12}` width specifier
    // counts the ANSI escape bytes of an already-styled string, so in color
    // mode the column never lines up.
    let _ = writeln!(
        out,
        "  {}  {}",
        style.dim(&format!("{:<12}", finding.kind.as_str())),
        style.bold(&finding.variable)
    );
    push_text_locations(out, &finding.locations, style);
    let _ = writeln!(out, "    {}", finding.summary);
    let _ = writeln!(out, "    {} {}", style.dim("fix:"), finding.fix);
}

fn push_text_locations(out: &mut String, locations: &[Location], style: &Style) {
    let label = location_label(locations);
    if let [location] = locations {
        let _ = writeln!(
            out,
            "    {} {}",
            style.dim(label),
            format_location(location, style)
        );
        return;
    }

    let _ = writeln!(out, "    {}:", style.dim(label));
    for location in locations {
        let _ = writeln!(out, "      {}", format_location(location, style));
    }
}

fn location_label(locations: &[Location]) -> &'static str {
    let roles: BTreeSet<Role> = locations.iter().map(|location| location.role).collect();
    if roles.len() == 1 {
        match roles.iter().next().copied() {
            Some(Role::Usage) => "used at",
            Some(Role::Secret) => "found in",
            Some(Role::Declaration) => "declared at",
            None => "at",
        }
    } else {
        "at"
    }
}

fn format_location(location: &Location, style: &Style) -> String {
    match location.line {
        Some(line) => format!(
            "{}:{}",
            style.dim(&location.path),
            style.dim(&line.to_string())
        ),
        None => style.dim(&location.path),
    }
}

fn format_summary(summary: &Summary) -> String {
    if summary.total == 0 {
        return "Summary: 0 findings".to_owned();
    }

    let mut parts = Vec::new();
    for (count, label) in [
        (summary.critical, "critical"),
        (summary.error, "error"),
        (summary.warning, "warning"),
        (summary.info, "info"),
    ] {
        if count > 0 {
            parts.push(format!(
                "{count} {}",
                if count == 1 { label } else { plural(label) }
            ));
        }
    }
    let total = if summary.total == 1 {
        "1 finding".to_owned()
    } else {
        format!("{} findings", summary.total)
    };
    format!("Summary: {} ({total})", parts.join(", "))
}

fn plural(label: &str) -> &'static str {
    match label {
        "critical" => "critical",
        "error" => "errors",
        "warning" => "warnings",
        "info" => "info",
        _ => "findings",
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Color is enabled only for terminals, unless NO_COLOR is set or TERM=dumb.
pub fn color_enabled() -> bool {
    color_enabled_for(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("TERM").ok().as_deref(),
    )
}

fn color_enabled_for(is_terminal: bool, no_color: bool, term: Option<&str>) -> bool {
    is_terminal && !no_color && !matches!(term, Some("dumb"))
}

struct Style {
    enabled: bool,
}

impl Style {
    fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    fn paint(&self, code: &str, value: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{value}\x1b[0m")
        } else {
            value.to_owned()
        }
    }

    fn bold(&self, value: &str) -> String {
        self.paint("1", value)
    }

    fn dim(&self, value: &str) -> String {
        self.paint("2", value)
    }

    fn severity(&self, severity: Severity, value: &str) -> String {
        match severity {
            Severity::Critical | Severity::Error => self.paint("1;31", value),
            Severity::Warning => self.paint("1;33", value),
            Severity::Info => self.paint("1;36", value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FindingKind;

    fn sample_audit() -> Audit {
        Audit {
            root_display: ".".to_owned(),
            files_scanned: 4,
            findings: vec![
                Finding::new(
                    FindingKind::Secret,
                    Severity::Critical,
                    "API_KEY",
                    "A likely secret value is stored in .env, which is not ignored by .gitignore.",
                    "Remove it.",
                    vec![Location::secret(".env", 2)],
                )
                .with_gitignored(false),
                Finding::new(
                    FindingKind::Missing,
                    Severity::Error,
                    "REGION",
                    "Missing declaration.",
                    "Add it.",
                    vec![Location::usage("src/app.ts", 3)],
                ),
            ],
        }
    }

    #[test]
    fn json_contains_stable_top_level_fields() {
        let output = render_json(&sample_audit()).unwrap();
        assert!(output.contains("\"schema_version\": 1"));
        assert!(output.contains("\"root\": \".\""));
        assert!(output.contains("\"files_scanned\": 4"));
        assert!(output.contains("\"kinds\""));
        assert!(output.contains("\"missing\": 1"));
        assert!(output.contains("\"secret\": 1"));
        assert!(!output.contains("\u{1b}["));
    }

    #[test]
    fn markdown_groups_by_severity() {
        let output = render_markdown(&sample_audit());
        assert!(output.contains("## Critical (1)"));
        assert!(output.contains("## Error (1)"));
        assert!(output.contains("`API_KEY` — secret"));
        assert!(output.contains("`src/app.ts:3`"));
    }

    #[test]
    fn sarif_is_valid_and_points_at_locations() {
        let output = render_sarif(&sample_audit()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "EnvAudit");
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            5
        );

        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "envaudit/secret");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".env"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            2
        );
        assert!(
            results[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("Fix: Remove it.")
        );
        assert_eq!(results[1]["ruleId"], "envaudit/missing");
        assert_eq!(results[1]["level"], "error");
    }

    #[test]
    fn sarif_prefixes_the_scanned_subdirectory() {
        let mut audit = sample_audit();
        audit.root_display = "services/api".to_owned();
        audit.findings[1].locations[0].path = "src\\app.ts".to_owned();

        let output = render_sarif(&audit).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "services/api/src/app.ts"
        );
    }

    #[test]
    fn sarif_is_still_a_valid_document_without_findings() {
        let audit = Audit {
            root_display: ".".to_owned(),
            files_scanned: 1,
            findings: Vec::new(),
        };
        let output = render_sarif(&audit).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(value["runs"][0]["results"].as_array().unwrap().is_empty());
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn text_output_is_plain_without_color() {
        let output = render_text(
            &sample_audit(),
            TextOptions {
                color: false,
                fail_on: Some("missing"),
                failing: true,
            },
        );
        assert!(!output.contains("\u{1b}["));
        assert!(output.contains("critical (1)"));
        assert!(output.contains("Summary: 1 critical, 1 error (2 findings)"));
        assert!(output.contains("Result: fail (--fail-on missing matched findings)"));
    }

    #[test]
    fn text_output_handles_no_findings() {
        let audit = Audit {
            root_display: ".".to_owned(),
            files_scanned: 1,
            findings: Vec::new(),
        };
        let output = render_text(
            &audit,
            TextOptions {
                color: false,
                fail_on: None,
                failing: false,
            },
        );
        assert!(output.contains("No findings."));
        assert!(output.contains("Summary: 0 findings"));
        assert!(output.contains("Result: report only"));
    }

    #[test]
    fn color_requires_a_terminal_and_respects_no_color() {
        assert!(color_enabled_for(true, false, Some("xterm-256color")));
        assert!(!color_enabled_for(false, false, Some("xterm-256color")));
        assert!(!color_enabled_for(true, true, Some("xterm-256color")));
        assert!(!color_enabled_for(true, false, Some("dumb")));
    }

    #[test]
    fn color_is_applied_when_requested() {
        let output = render_text(
            &sample_audit(),
            TextOptions {
                color: true,
                fail_on: None,
                failing: false,
            },
        );
        assert!(output.contains("\u{1b}[1;31m"));
    }

    #[test]
    fn color_mode_pads_the_kind_column_before_styling() {
        let output = render_text(
            &sample_audit(),
            TextOptions {
                color: true,
                fail_on: None,
                failing: false,
            },
        );
        // The 7-character kind name is padded to 12 columns inside the style,
        // not after the escape bytes were counted.
        assert!(output.contains("\u{1b}[2mmissing     \u{1b}[0m  \u{1b}[1mREGION\u{1b}[0m"));
    }

    #[test]
    fn plain_mode_pads_the_kind_column() {
        let output = render_text(
            &sample_audit(),
            TextOptions {
                color: false,
                fail_on: None,
                failing: false,
            },
        );
        assert!(output.contains("  missing       REGION"));
        assert!(output.contains("  secret        API_KEY"));
    }
}
