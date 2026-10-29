use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::analyze::Audit;
use crate::declarations::Declarations;
use crate::dotenv::{self, EnvKind};
use crate::model::FindingKind;

const DEFAULT_EXAMPLE: &str = ".env.example";
const HEADER: &str =
    "# Added by EnvAudit\n# Referenced in code or set at runtime. Values are intentionally blank.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixOutcome {
    /// Example file that was written, relative to the scan root.
    pub path: String,
    /// Variables appended to the file, in sorted order.
    pub added: Vec<String>,
    /// Whether the example file did not exist before this run.
    pub created: bool,
}

/// Appends missing and undocumented variables to the primary example env file.
///
/// The fix is intentionally narrow: it only adds names with empty values, never
/// edits a real env file, never removes an entry, and never writes a secret.
/// Returns `None` when there is nothing eligible to add.
pub fn apply(
    root: &Path,
    declarations: &Declarations,
    audit: &Audit,
) -> Result<Option<FixOutcome>> {
    let mut wanted = BTreeSet::new();
    for finding in &audit.findings {
        if matches!(
            finding.kind,
            FindingKind::Missing | FindingKind::Undocumented
        ) && dotenv::is_valid_env_key(&finding.variable)
        {
            wanted.insert(finding.variable.clone());
        }
    }
    if wanted.is_empty() {
        return Ok(None);
    }

    // Without an existing example file there are no `undocumented` findings,
    // so also seed the new file with the names already set at runtime. Only
    // names are written; values never leave the real env file.
    if !declarations.has_example() {
        for declaration in &declarations.items {
            if declaration.env_kind == Some(EnvKind::Real)
                && dotenv::is_valid_env_key(&declaration.name)
            {
                wanted.insert(declaration.name.clone());
            }
        }
    }

    let relative = declarations.primary_example().unwrap_or(DEFAULT_EXAMPLE);
    let path = root.join(relative);
    let created = !path.exists();
    let content = if created {
        String::new()
    } else {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read example env file `{relative}`"))?
    };

    let existing: BTreeSet<String> = if content.trim().is_empty() {
        BTreeSet::new()
    } else {
        dotenv::parse(&content)
            .with_context(|| format!("failed to parse example env file `{relative}`"))?
            .into_iter()
            .map(|entry| entry.key)
            .collect()
    };
    let added: Vec<String> = wanted.difference(&existing).cloned().collect();
    if added.is_empty() {
        return Ok(None);
    }

    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut updated = content;
    if !updated.is_empty() {
        if !updated.ends_with('\n') {
            updated.push_str(newline);
        }
        let blank = format!("{newline}{newline}");
        if !updated.ends_with(&blank) {
            updated.push_str(newline);
        }
    }
    for line in HEADER.lines() {
        updated.push_str(line);
        updated.push_str(newline);
    }
    for name in &added {
        updated.push_str(name);
        updated.push('=');
        updated.push_str(newline);
    }

    fs::write(&path, updated)
        .with_context(|| format!("failed to write example env file `{relative}`"))?;

    Ok(Some(FixOutcome {
        path: relative.to_owned(),
        added,
        created,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::TempDir;

    use crate::analyze;
    use crate::declarations;
    use crate::scan;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn load(root: &Path) -> (Declarations, Audit) {
        let collected = scan::collect(root).unwrap();
        let declarations = declarations::collect(&collected).unwrap();
        let audit = analyze::analyze(&collected, &declarations);
        (declarations, audit)
    }

    fn fixture() -> TempDir {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join("src/app.ts"),
            "const a = process.env.DEPLOY_REGION;\nconst b = process.env.EXISTING;\n",
        );
        write(
            &temp.path().join(".env"),
            "EXISTING=one\nUNDOCUMENTED=two\n",
        );
        write(&temp.path().join(".env.example"), "EXISTING=one\n");
        temp
    }

    #[test]
    fn adds_missing_and_undocumented_names_to_the_primary_example() {
        let temp = fixture();
        let (declarations, audit) = load(temp.path());
        let outcome = apply(temp.path(), &declarations, &audit).unwrap().unwrap();
        assert_eq!(outcome.path, ".env.example");
        assert!(!outcome.created);
        assert_eq!(outcome.added, vec!["DEPLOY_REGION", "UNDOCUMENTED"]);

        let content = fs::read_to_string(temp.path().join(".env.example")).unwrap();
        assert!(content.contains("EXISTING=one"));
        assert!(content.contains("DEPLOY_REGION="));
        assert!(content.contains("UNDOCUMENTED="));
        assert_eq!(content.matches("EXISTING=").count(), 1);
        assert!(content.contains("# Added by EnvAudit"));
    }

    #[test]
    fn creates_an_example_file_when_none_exists() {
        let temp = tempfile::tempdir().unwrap();
        write(
            &temp.path().join("src/app.ts"),
            "const url = process.env.API_URL;\n",
        );
        let (declarations, audit) = load(temp.path());
        let outcome = apply(temp.path(), &declarations, &audit).unwrap().unwrap();
        assert!(outcome.created);
        let content = fs::read_to_string(temp.path().join(".env.example")).unwrap();
        assert!(content.starts_with("# Added by EnvAudit\n"));
        assert!(content.contains("API_URL="));
    }

    #[test]
    fn is_idempotent_and_leaves_real_env_files_alone() {
        let temp = fixture();
        let real_before = fs::read_to_string(temp.path().join(".env")).unwrap();
        let (declarations, audit) = load(temp.path());
        apply(temp.path(), &declarations, &audit).unwrap().unwrap();
        let first = fs::read_to_string(temp.path().join(".env.example")).unwrap();

        let (declarations, audit) = load(temp.path());
        assert!(apply(temp.path(), &declarations, &audit).unwrap().is_none());
        let second = fs::read_to_string(temp.path().join(".env.example")).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::read_to_string(temp.path().join(".env")).unwrap(),
            real_before
        );
    }

    #[test]
    fn preserves_crlf_line_endings() {
        let temp = fixture();
        fs::write(temp.path().join(".env.example"), "EXISTING=one\r\n").unwrap();
        let (declarations, audit) = load(temp.path());
        apply(temp.path(), &declarations, &audit).unwrap().unwrap();
        let content = fs::read_to_string(temp.path().join(".env.example")).unwrap();
        assert!(content.contains("\r\nDEPLOY_REGION=\r\n"));
        assert!(!content.contains("\nDEPLOY_REGION=\n"));
    }

    #[test]
    fn ignores_findings_that_are_not_documentation_gaps() {
        let temp = fixture();
        let (declarations, _) = load(temp.path());
        let audit = Audit {
            root_display: ".".to_owned(),
            files_scanned: 1,
            findings: vec![crate::model::Finding::new(
                FindingKind::Secret,
                crate::model::Severity::Critical,
                "API_TOKEN",
                "secret",
                "rotate it",
                vec![crate::model::Location::secret(".env", 1)],
            )],
        };
        assert!(apply(temp.path(), &declarations, &audit).unwrap().is_none());
    }
}
