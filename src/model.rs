use serde::Serialize;

/// Ordered from most to least urgent; the order is used for report grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Critical, Self::Error, Self::Warning, Self::Info];

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Missing,
    Unused,
    Undocumented,
    Secret,
    Duplicate,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unused => "unused",
            Self::Undocumented => "undocumented",
            Self::Secret => "secret",
            Self::Duplicate => "duplicate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Usage,
    Declaration,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Location {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub role: Role,
}

impl Location {
    pub fn usage(path: impl Into<String>, line: usize) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            role: Role::Usage,
        }
    }

    pub fn declaration(path: impl Into<String>, line: usize) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            role: Role::Declaration,
        }
    }

    pub fn secret(path: impl Into<String>, line: usize) -> Self {
        Self {
            path: path.into(),
            line: Some(line),
            role: Role::Secret,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub variable: String,
    pub summary: String,
    pub fix: String,
    pub locations: Vec<Location>,
    /// Present only for `secret` findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gitignored: Option<bool>,
}

impl Finding {
    pub fn new(
        kind: FindingKind,
        severity: Severity,
        variable: impl Into<String>,
        summary: impl Into<String>,
        fix: impl Into<String>,
        locations: Vec<Location>,
    ) -> Self {
        Self {
            kind,
            severity,
            variable: variable.into(),
            summary: summary.into(),
            fix: fix.into(),
            locations,
            gitignored: None,
        }
    }

    pub fn with_gitignored(mut self, gitignored: bool) -> Self {
        self.gitignored = Some(gitignored);
        self
    }
}
