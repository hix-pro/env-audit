use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

/// A variable reference found in source code or configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Usage {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    JavaScript,
    Rust,
    Go,
    Shell,
}

impl Language {
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" => Some(Self::JavaScript),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "sh" | "bash" | "zsh" | "ksh" | "dash" => Some(Self::Shell),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::JavaScript => "JavaScript/TypeScript",
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::Shell => "shell",
        }
    }
}

static JS_DOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:process|import\.meta|Bun)\.env(?:\?)?\.([A-Za-z_][A-Za-z0-9_]*)")
        .expect("valid JavaScript dot-access regex")
});

static JS_BRACKET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:process|import\.meta|Bun)\.env\s*\[\s*(?:"([A-Za-z_][A-Za-z0-9_]*)"|'([A-Za-z_][A-Za-z0-9_]*)')\s*\]"#,
    )
    .expect("valid JavaScript bracket-access regex")
});

static JS_DENO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bDeno\.env\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\)"#)
        .expect("valid Deno regex")
});

static RUST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:std::)?env::var(?:_os)?\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)"#)
        .expect("valid Rust regex")
});

static GO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bos\.(?:Getenv|LookupEnv)\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)"#)
        .expect("valid Go regex")
});

static SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=+?][^}]*)?\}|([A-Za-z_][A-Za-z0-9_]*))")
        .expect("valid shell regex")
});

static YAML_INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=+?][^}]*)?\}").expect("valid YAML regex")
});

/// Scans one source file for environment variable usage.
pub fn scan_language(language: Language, content: &str) -> Vec<Usage> {
    let mut hits = BTreeSet::new();
    match language {
        Language::JavaScript => {
            collect(&JS_DOT, content, &[1], &mut hits);
            collect(&JS_BRACKET, content, &[1, 2], &mut hits);
            collect(&JS_DENO, content, &[1], &mut hits);
        }
        Language::Rust => collect(&RUST, content, &[1], &mut hits),
        Language::Go => collect(&GO, content, &[1], &mut hits),
        Language::Shell => collect(&SHELL, content, &[1, 2], &mut hits),
    }
    into_usage(hits)
}

/// Finds `${NAME}` and `${NAME:-default}` interpolations used by Compose and
/// GitHub Actions YAML.
pub fn scan_yaml_interpolations(content: &str) -> Vec<Usage> {
    let mut hits = BTreeSet::new();
    collect(&YAML_INTERPOLATION, content, &[1], &mut hits);
    into_usage(hits)
}

fn collect(regex: &Regex, content: &str, groups: &[usize], hits: &mut BTreeSet<(usize, String)>) {
    for captures in regex.captures_iter(content) {
        let Some(found) = groups
            .iter()
            .find_map(|group| captures.get(*group).map(|m| m.as_str()))
        else {
            continue;
        };
        let Some(whole) = captures.get(0) else {
            continue;
        };
        hits.insert((line_number(content, whole.start()), found.to_owned()));
    }
}

fn into_usage(hits: BTreeSet<(usize, String)>) -> Vec<Usage> {
    hits.into_iter()
        .map(|(line, name)| Usage { name, line })
        .collect()
}

/// 1-based line number for a byte offset.
pub(crate) fn line_number(content: &str, offset: usize) -> usize {
    let end = offset.min(content.len());
    content.as_bytes()[..end]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(usages: &[Usage]) -> Vec<&str> {
        usages.iter().map(|usage| usage.name.as_str()).collect()
    }

    #[test]
    fn detects_process_env_dot_access() {
        let found = scan_language(
            Language::JavaScript,
            "const key = process.env.STRIPE_KEY;\n",
        );
        assert_eq!(
            found,
            vec![Usage {
                name: "STRIPE_KEY".into(),
                line: 1
            }]
        );
    }

    #[test]
    fn detects_process_env_bracket_access() {
        let code =
            "const a = process.env[\"DATABASE_URL\"];\nconst b = process.env['REDIS_URL'];\n";
        let found = scan_language(Language::JavaScript, code);
        assert_eq!(names(&found), vec!["DATABASE_URL", "REDIS_URL"]);
        assert_eq!(found[1].line, 2);
    }

    #[test]
    fn detects_import_meta_env() {
        let found = scan_language(
            Language::JavaScript,
            "const url = import.meta.env.VITE_API_URL;\n",
        );
        assert_eq!(names(&found), vec!["VITE_API_URL"]);
    }

    #[test]
    fn detects_bun_env() {
        let found = scan_language(Language::JavaScript, "const queue = Bun.env.QUEUE_NAME;\n");
        assert_eq!(names(&found), vec!["QUEUE_NAME"]);
    }

    #[test]
    fn detects_deno_env_get() {
        let found = scan_language(
            Language::JavaScript,
            "const token = Deno.env.get(\"DENO_TOKEN\");\n",
        );
        assert_eq!(names(&found), vec!["DENO_TOKEN"]);
    }

    #[test]
    fn detects_rust_env_var() {
        let code = "let a = env::var(\"APP_ENV\")?;\nlet b = std::env::var(\"DATABASE_URL\")?;\nlet c = env::var_os(\"HOME\")?;\n";
        let found = scan_language(Language::Rust, code);
        assert_eq!(names(&found), vec!["APP_ENV", "DATABASE_URL", "HOME"]);
    }

    #[test]
    fn detects_go_getenv_and_lookup_env() {
        let code = "a := os.Getenv(\"PORT\")\nb, ok := os.LookupEnv(\"DEBUG\")\n";
        let found = scan_language(Language::Go, code);
        assert_eq!(names(&found), vec!["PORT", "DEBUG"]);
    }

    #[test]
    fn detects_shell_variable_forms() {
        let code = "echo \"$PLAIN ${BRACED} ${DEFAULTED:-localhost} ${ALT:=fallback}\"\n";
        let found = scan_language(Language::Shell, code);
        assert_eq!(names(&found), vec!["ALT", "BRACED", "DEFAULTED", "PLAIN"]);
    }

    #[test]
    fn ignores_shell_positional_and_special_parameters() {
        let found = scan_language(Language::Shell, "echo \"$1 $? $$ $#\"\n");
        assert!(found.is_empty());
    }

    #[test]
    fn detects_yaml_interpolations() {
        let found = scan_yaml_interpolations(
            "url: ${DATABASE_URL}\nhost: ${HOST:-localhost}\nref: ${{ secrets.TOKEN }}\n",
        );
        assert_eq!(names(&found), vec!["DATABASE_URL", "HOST"]);
    }

    #[test]
    fn reports_correct_line_numbers() {
        let code = "first\nsecond\nconst x = process.env.THIRD;\n";
        let found = scan_language(Language::JavaScript, code);
        assert_eq!(found[0].line, 3);
    }

    #[test]
    fn deduplicates_identical_references_on_the_same_line() {
        let code = "const a = process.env.NAME + process.env.NAME;\n";
        let found = scan_language(Language::JavaScript, code);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn maps_extensions_to_languages() {
        assert_eq!(Language::from_extension("tsx"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("go"), Some(Language::Go));
        assert_eq!(Language::from_extension("toml"), None);
    }
}
