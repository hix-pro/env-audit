use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::dotenv::{self, EnvKind};
use crate::scan::{self, Collected, ConfigKind};
use crate::yaml;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    Dotenv,
    Compose,
    Workflow,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dotenv => "env file",
            Self::Compose => "Compose",
            Self::Workflow => "workflow",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Declaration {
    pub name: String,
    /// Present only for dotenv declarations. Never rendered in reports.
    pub value: Option<String>,
    pub path: String,
    pub line: usize,
    pub origin: Origin,
    pub env_kind: Option<EnvKind>,
}

#[derive(Debug, Default)]
pub struct Declarations {
    pub items: Vec<Declaration>,
    pub example_files: BTreeSet<String>,
    pub real_env_files: BTreeSet<String>,
}

impl Declarations {
    pub fn has_example(&self) -> bool {
        !self.example_files.is_empty()
    }

    pub fn primary_example(&self) -> Option<&str> {
        if self.example_files.contains(".env.example") {
            Some(".env.example")
        } else {
            self.example_files.iter().next().map(String::as_str)
        }
    }
}

/// Parses every declaration source and follows Compose `env_file` references
/// within the scan root.
pub fn collect(collected: &Collected) -> Result<Declarations> {
    let mut declarations = Declarations::default();
    let mut seen_env_files = BTreeSet::new();

    for file in &collected.env_files {
        seen_env_files.insert(file.relative.clone());
        add_env_file(&mut declarations, file)?;
    }

    let mut env_file_references = Vec::new();
    for config in &collected.configs {
        match config.kind {
            ConfigKind::Compose => {
                let parsed = yaml::parse_compose(&config.content).with_context(|| {
                    format!("failed to parse Compose file `{}`", config.relative)
                })?;
                add_yaml_keys(
                    &mut declarations,
                    &parsed,
                    &config.relative,
                    Origin::Compose,
                );
                env_file_references.extend(
                    parsed
                        .env_file_paths
                        .into_iter()
                        .map(|reference| (config.relative.clone(), reference)),
                );
            }
            ConfigKind::Workflow => {
                let parsed = yaml::parse_workflow(&config.content)
                    .with_context(|| format!("failed to parse workflow `{}`", config.relative))?;
                add_yaml_keys(
                    &mut declarations,
                    &parsed,
                    &config.relative,
                    Origin::Workflow,
                );
            }
        }
    }

    for (compose_file, reference) in env_file_references {
        if reference.contains('$') {
            // Interpolated paths cannot be resolved without Compose's runtime
            // environment.
            continue;
        }
        let parent = Path::new(&compose_file)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let candidate = collected.root.join(parent).join(&reference);
        let env_file =
            scan::read_referenced_env_file(&collected.root, &candidate).with_context(|| {
                format!("failed to read env_file `{reference}` referenced by `{compose_file}`")
            })?;
        let Some(env_file) = env_file else {
            continue;
        };
        if seen_env_files.insert(env_file.relative.clone()) {
            add_env_file(&mut declarations, &env_file)?;
        }
    }

    declarations.items.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(declarations)
}

fn add_env_file(declarations: &mut Declarations, file: &scan::RawEnvFile) -> Result<()> {
    let entries = dotenv::parse(&file.content)
        .with_context(|| format!("failed to parse env file `{}`", file.relative))?;
    match file.kind {
        EnvKind::Real => {
            declarations.real_env_files.insert(file.relative.clone());
        }
        EnvKind::Example => {
            declarations.example_files.insert(file.relative.clone());
        }
    }
    for entry in entries {
        declarations.items.push(Declaration {
            name: entry.key,
            value: Some(entry.value),
            path: file.relative.clone(),
            line: entry.line,
            origin: Origin::Dotenv,
            env_kind: Some(file.kind),
        });
    }
    Ok(())
}

fn add_yaml_keys(
    declarations: &mut Declarations,
    parsed: &yaml::ParsedYaml,
    path: &str,
    origin: Origin,
) {
    for key in &parsed.env_keys {
        declarations.items.push(Declaration {
            name: key.key.clone(),
            value: None,
            path: path.to_owned(),
            line: key.line,
            origin,
            env_kind: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn collects_env_compose_workflow_and_referenced_env_files() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join(".env.example"), "A=example\n");
        write(&temp.path().join(".env"), "B=real\n");
        write(
            &temp.path().join("compose.yaml"),
            "services:\n  api:\n    environment:\n      C: value\n    env_file:\n      - config/custom.env\n",
        );
        write(
            &temp.path().join(".github/workflows/ci.yml"),
            "env:\n  D: yes\n",
        );
        write(&temp.path().join("config/custom.env"), "E=five\n");

        let collected = scan::collect(temp.path()).unwrap();
        let declarations = collect(&collected).unwrap();
        let names: Vec<&str> = declarations
            .items
            .iter()
            .map(|declaration| declaration.name.as_str())
            .collect();
        for expected in ["A", "B", "C", "D", "E"] {
            assert!(names.contains(&expected), "missing {expected} in {names:?}");
        }
        assert!(declarations.has_example());
        assert_eq!(declarations.primary_example(), Some(".env.example"));
        assert!(declarations.real_env_files.contains("config/custom.env"));
    }

    #[test]
    fn records_duplicate_dotenv_declarations() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join(".env"), "DUP=one\nDUP=two\n");
        write(&temp.path().join(".env.local"), "DUP=three\n");
        let collected = scan::collect(temp.path()).unwrap();
        let declarations = collect(&collected).unwrap();
        let duplicates: Vec<&Declaration> = declarations
            .items
            .iter()
            .filter(|declaration| declaration.name == "DUP")
            .collect();
        assert_eq!(duplicates.len(), 3);
        assert!(
            duplicates
                .iter()
                .all(|declaration| declaration.value.is_some())
        );
    }

    #[test]
    fn parse_errors_include_the_file_path() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join(".env"), "BROKEN\n");
        let collected = scan::collect(temp.path()).unwrap();
        let error = collect(&collected).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(".env"));
        assert!(message.contains("KEY=VALUE"));
    }
}
