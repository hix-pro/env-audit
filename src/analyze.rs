use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::declarations::{Declaration, Declarations, Origin};
use crate::dotenv::EnvKind;
use crate::gitignore;
use crate::model::{Finding, FindingKind, Location, Severity};
use crate::patterns;
use crate::scan::Collected;

#[derive(Debug)]
pub struct Audit {
    pub root_display: String,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
}

impl Audit {
    pub fn count(&self, kind: FindingKind) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.kind == kind)
            .count()
    }
}

/// Turns raw usages and declarations into sorted findings.
pub fn analyze(collected: &Collected, declarations: &Declarations) -> Audit {
    let usages = collect_usages(collected);
    let used_names: BTreeSet<&str> = usages.keys().map(String::as_str).collect();

    let mut all_names = BTreeSet::new();
    let mut example_by_name: BTreeMap<&str, Vec<&Declaration>> = BTreeMap::new();
    let mut real_by_name: BTreeMap<&str, Vec<&Declaration>> = BTreeMap::new();
    let mut real_dotenv_by_name: BTreeMap<&str, Vec<&Declaration>> = BTreeMap::new();
    let mut secrets: BTreeMap<(&str, &str), Vec<&Declaration>> = BTreeMap::new();

    for declaration in &declarations.items {
        let name = declaration.name.as_str();
        all_names.insert(name);
        match declaration.env_kind {
            Some(EnvKind::Example) => {
                example_by_name.entry(name).or_default().push(declaration);
            }
            Some(EnvKind::Real) => {
                real_by_name.entry(name).or_default().push(declaration);
                real_dotenv_by_name
                    .entry(name)
                    .or_default()
                    .push(declaration);
                if let Some(value) = &declaration.value {
                    if is_secret_key(name) && is_likely_secret_value(value) {
                        secrets
                            .entry((declaration.path.as_str(), name))
                            .or_default()
                            .push(declaration);
                    }
                }
            }
            None => {
                if matches!(declaration.origin, Origin::Compose | Origin::Workflow) {
                    real_by_name.entry(name).or_default().push(declaration);
                }
            }
        }
    }

    let mut findings = Vec::new();

    for (name, locations) in &usages {
        if !all_names.contains(name.as_str()) {
            findings.push(Finding::new(
                FindingKind::Missing,
                Severity::Error,
                name,
                "Referenced in scanned code but not declared in any env file, Compose environment, or workflow env map.",
                format!(
                    "Add {name} to .env.example and the deployment environment, or remove the reference."
                ),
                locations.iter().cloned().collect(),
            ));
        }
    }

    for (name, declarations) in &example_by_name {
        if !used_names.contains(name) {
            findings.push(Finding::new(
                FindingKind::Unused,
                Severity::Warning,
                *name,
                "Declared in an example env file but never referenced in scanned code.",
                format!("Remove {name} from the example file or add the code that reads it."),
                declaration_locations(declarations),
            ));
        }
    }

    if declarations.has_example() {
        let example_names: BTreeSet<&str> = example_by_name.keys().copied().collect();
        let example = declarations.primary_example().unwrap_or(".env.example");
        for (name, declarations) in &real_by_name {
            if !example_names.contains(name) {
                findings.push(Finding::new(
                    FindingKind::Undocumented,
                    Severity::Warning,
                    *name,
                    "Set in runtime configuration but absent from the example env file.",
                    format!("Add {name} to {example} so new contributors can discover it."),
                    declaration_locations(declarations),
                ));
            }
        }
    }

    for ((path, name), declarations) in &secrets {
        let gitignored = gitignore::is_ignored(&collected.root, path);
        let (severity, summary, fix) = if gitignored {
            (
                Severity::Warning,
                format!(
                    "A likely secret value is stored in {path}; the file is ignored by .gitignore."
                ),
                "Rotate the credential if it was ever committed, and keep the file out of version control."
                    .to_owned(),
            )
        } else {
            (
                Severity::Critical,
                format!(
                    "A likely secret value is stored in {path}, which is not ignored by .gitignore."
                ),
                format!(
                    "Remove the value from {path}, rotate the credential, and add {path} to .gitignore."
                ),
            )
        };
        findings.push(
            Finding::new(
                FindingKind::Secret,
                severity,
                *name,
                summary,
                fix,
                declarations
                    .iter()
                    .map(|declaration| Location::secret(declaration.path.clone(), declaration.line))
                    .collect(),
            )
            .with_gitignored(gitignored),
        );
    }

    for (name, declarations) in &real_dotenv_by_name {
        if declarations.len() < 2 {
            continue;
        }
        let values: BTreeSet<&str> = declarations
            .iter()
            .filter_map(|declaration| declaration.value.as_deref())
            .collect();
        let conflict = values.len() > 1;
        let summary = if conflict {
            "Declared with different values across real env files."
        } else {
            "Declared more than once across real env files."
        };
        findings.push(Finding::new(
            FindingKind::Duplicate,
            Severity::Info,
            *name,
            summary,
            "Keep one source of truth, or document the override intentionally.",
            declaration_locations(declarations),
        ));
    }

    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.variable.cmp(&right.variable))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.summary.cmp(&right.summary))
            .then_with(|| left.locations.cmp(&right.locations))
    });

    Audit {
        root_display: collected.root_display.clone(),
        files_scanned: collected.files_scanned,
        findings,
    }
}

fn collect_usages(collected: &Collected) -> BTreeMap<String, BTreeSet<Location>> {
    let mut usages: BTreeMap<String, BTreeSet<Location>> = BTreeMap::new();

    for source in &collected.sources {
        for usage in patterns::scan_language(source.language, &source.content) {
            usages
                .entry(usage.name)
                .or_default()
                .insert(Location::usage(source.relative.clone(), usage.line));
        }
    }

    for config in &collected.configs {
        for usage in patterns::scan_yaml_interpolations(&config.content) {
            usages
                .entry(usage.name)
                .or_default()
                .insert(Location::usage(config.relative.clone(), usage.line));
        }
    }

    usages
}

fn declaration_locations(declarations: &[&Declaration]) -> Vec<Location> {
    declarations
        .iter()
        .map(|declaration| Location::declaration(declaration.path.clone(), declaration.line))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

static SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|APIKEY|KEY)(?:_|$)")
        .expect("valid secret key regex")
});

const NON_SECRET_SUFFIXES: &[&str] = &[
    "_PATH",
    "_FILE",
    "_NAME",
    "_URL",
    "_URI",
    "_PREFIX",
    "_SUFFIX",
    "_TYPE",
    "_ALGORITHM",
    "_SIZE",
    "_ID",
    "_COUNT",
    "_ENABLED",
    "_TTL",
    "_EXPIRES_AT",
    "_EXPIRY",
];

pub(crate) fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_uppercase();
    if normalized.starts_with("PUBLIC_") || normalized.contains("_PUBLIC_") {
        return false;
    }
    if NON_SECRET_SUFFIXES
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
    {
        return false;
    }
    SECRET_KEY.is_match(&normalized)
}

pub(crate) fn is_likely_secret_value(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 8 || !value.chars().any(char::is_alphanumeric) {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    const PLACEHOLDER_MARKERS: &[&str] = &[
        "changeme",
        "change_me",
        "change-me",
        "replace_me",
        "replace-me",
        "placeholder",
        "example",
        "dummy",
        "your_",
        "your-",
        "<your",
        "xxxx",
        "****",
        "redacted",
        "todo",
        "fixme",
        "${",
        "{{",
    ];
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return false;
    }

    const EXACT_PLACEHOLDERS: &[&str] = &[
        "password",
        "secret",
        "token",
        "development",
        "production",
        "localhost",
        "true",
        "false",
        "none",
        "null",
    ];
    if EXACT_PLACEHOLDERS.contains(&lower.as_str()) {
        return false;
    }

    let mut chars = value.chars();
    let first = chars.next().unwrap_or_default();
    if chars.all(|ch| ch == first) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declarations;
    use crate::scan;
    use std::fs;
    use std::path::Path;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn audit_repo(temp: &tempfile::TempDir) -> Audit {
        let collected = scan::collect(temp.path()).unwrap();
        let declarations = declarations::collect(&collected).unwrap();
        analyze(&collected, &declarations)
    }

    #[test]
    fn reports_all_finding_kinds() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(".env.example"),
            "USED=value\nUNUSED_FLAG=true\n",
        );
        write(
            &temp.path().join(".env"),
            "USED=value\nUNDOCUMENTED_SETTING=yes\nAPI_KEY_REAL=plainvalue\n",
        );
        write(&temp.path().join(".env.local"), "USED=other\n");
        write(
            &temp.path().join("src/app.ts"),
            "process.env.USED;\nprocess.env.MISSING_VALUE;\n",
        );

        let audit = audit_repo(&temp);
        assert_eq!(audit.count(FindingKind::Missing), 1);
        assert_eq!(audit.count(FindingKind::Unused), 1);
        assert_eq!(audit.count(FindingKind::Undocumented), 2);
        assert_eq!(audit.count(FindingKind::Duplicate), 1);
    }

    #[test]
    fn secret_is_critical_when_not_gitignored_and_redacted() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(".env"),
            "STRIPE_SECRET_KEY=sk_live_abc123XYZ\n",
        );
        let audit = audit_repo(&temp);
        let secret = audit
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::Secret)
            .unwrap();
        assert_eq!(secret.severity, Severity::Critical);
        assert_eq!(secret.gitignored, Some(false));
        let rendered = serde_json::to_string(&secret).unwrap();
        assert!(!rendered.contains("sk_live_abc123XYZ"));
        assert!(rendered.contains("STRIPE_SECRET_KEY"));
    }

    #[test]
    fn secret_is_a_warning_when_gitignored() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(".env"),
            "GITHUB_TOKEN=ghp_abcdefghijklmnop\n",
        );
        write(&temp.path().join(".gitignore"), ".env\n");
        let audit = audit_repo(&temp);
        let secret = audit
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::Secret)
            .unwrap();
        assert_eq!(secret.severity, Severity::Warning);
        assert_eq!(secret.gitignored, Some(true));
    }

    #[test]
    fn placeholder_secrets_are_ignored() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join(".env"),
            "API_KEY=changeme\nTOKEN=your_token_here\nPASSWORD=short\nSECRET_KEY=xxxxxxxx\n",
        );
        let audit = audit_repo(&temp);
        assert_eq!(audit.count(FindingKind::Secret), 0);
    }

    #[test]
    fn secret_keys_are_detected_with_few_false_positives() {
        for key in [
            "API_KEY",
            "STRIPE_SECRET_KEY",
            "DB_PASSWORD",
            "GITHUB_TOKEN",
            "JWT_SECRET",
        ] {
            assert!(is_secret_key(key), "{key} should look secret");
        }
        for key in [
            "API_URL",
            "PUBLIC_KEY",
            "AWS_ACCESS_KEY_ID",
            "TOKENIZERS_PARALLELISM",
            "PASSWORD_RESET_PATH",
        ] {
            assert!(!is_secret_key(key), "{key} should not look secret");
        }
    }

    #[test]
    fn secret_values_require_realistic_length_and_content() {
        assert!(is_likely_secret_value("sk_live_abc123XYZ"));
        assert!(is_likely_secret_value("hunter2hunter2"));
        assert!(!is_likely_secret_value("short"));
        assert!(!is_likely_secret_value(""));
        assert!(!is_likely_secret_value("changeme"));
        assert!(!is_likely_secret_value("your_api_key_here"));
        assert!(!is_likely_secret_value("xxxxxxxx"));
        assert!(!is_likely_secret_value("${TOKEN}"));
    }

    #[test]
    fn example_only_declarations_are_not_undocumented_even_without_an_example() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join(".env"), "REAL=value\n");
        write(&temp.path().join("src/main.ts"), "process.env.REAL;\n");
        let audit = audit_repo(&temp);
        assert_eq!(audit.count(FindingKind::Undocumented), 0);
        assert_eq!(audit.count(FindingKind::Unused), 0);
    }
}
