use std::fs;
use std::path::Path;

use regex::Regex;

#[derive(Debug)]
struct Rule {
    base: String,
    regex: Regex,
    negated: bool,
    dir_only: bool,
    has_slash: bool,
    anchored: bool,
}

impl Rule {
    fn matches(&self, file: &str) -> bool {
        if self.matches_path(file, false) {
            return true;
        }

        let parts: Vec<&str> = file.split('/').filter(|part| !part.is_empty()).collect();
        for depth in 1..parts.len() {
            let directory = parts[..depth].join("/");
            if self.matches_path(&directory, true) {
                return true;
            }
        }
        false
    }

    fn matches_path(&self, path: &str, is_directory: bool) -> bool {
        if self.dir_only && !is_directory {
            return false;
        }
        let scoped = if self.base.is_empty() {
            path
        } else if let Some(rest) = path.strip_prefix(&self.base) {
            rest.strip_prefix('/').unwrap_or(rest)
        } else {
            return false;
        };
        if scoped.is_empty() {
            return false;
        }

        let candidate = if self.anchored || self.has_slash {
            scoped
        } else {
            scoped.rsplit('/').next().unwrap_or(scoped)
        };
        self.regex.is_match(candidate)
    }
}

/// Checks a path against `.gitignore` files from the scan root down to the
/// file's parent directory. This implements the common pattern subset used by
/// env files; it is not a complete Git ignore implementation.
pub fn is_ignored(root: &Path, relative: &str) -> bool {
    let normalized = relative.trim_start_matches("./").trim_start_matches('/');
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return false;
    }

    let mut rules = Vec::new();
    for depth in 0..parts.len() {
        let base = parts[..depth].join("/");
        let path = root.join(&base).join(".gitignore");
        match fs::read_to_string(&path) {
            Ok(content) => rules.extend(parse_rules(&content, &base)),
            // A missing file simply contributes no rules.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            // Any other failure would silently flip secret severities, so it
            // must be visible to the user without aborting the scan.
            Err(error) => {
                eprintln!("warning: failed to read `{}`: {error}", path.display());
            }
        }
    }

    evaluate(&rules, normalized)
}

fn evaluate(rules: &[Rule], file: &str) -> bool {
    let mut ignored = false;
    for rule in rules {
        if rule.matches(file) {
            ignored = !rule.negated;
        }
    }
    ignored
}

fn parse_rules(content: &str, base: &str) -> Vec<Rule> {
    content
        .lines()
        .filter_map(|line| parse_rule(line, base))
        .collect()
}

fn parse_rule(line: &str, base: &str) -> Option<Rule> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut pattern = line;
    let mut negated = false;
    let mut escaped_prefix = "";
    if let Some(rest) = pattern.strip_prefix('!') {
        negated = true;
        pattern = rest;
    } else if let Some(rest) = pattern.strip_prefix("\\!") {
        escaped_prefix = "!";
        pattern = rest;
    } else if let Some(rest) = pattern.strip_prefix("\\#") {
        escaped_prefix = "#";
        pattern = rest;
    }
    if pattern.is_empty() {
        return None;
    }

    let mut dir_only = false;
    if let Some(rest) = pattern.strip_suffix('/') {
        dir_only = true;
        pattern = rest;
    }
    let mut anchored = false;
    if let Some(rest) = pattern.strip_prefix('/') {
        anchored = true;
        pattern = rest;
    }
    if pattern.is_empty() {
        return None;
    }

    let pattern = format!("{escaped_prefix}{}", pattern.replace("\\ ", " "));
    let regex = glob_regex(&pattern)?;
    Some(Rule {
        base: base.to_owned(),
        regex,
        negated,
        dir_only,
        has_slash: pattern.contains('/'),
        anchored,
    })
}

fn glob_regex(pattern: &str) -> Option<Regex> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut regex = String::from("^");
    let mut index = 0;

    while index < chars.len() {
        match chars[index] {
            '*' => {
                let start = index;
                while index < chars.len() && chars[index] == '*' {
                    index += 1;
                }
                let double = index - start >= 2;
                if double && index < chars.len() && chars[index] == '/' {
                    regex.push_str("(?:.*/)?");
                    index += 1;
                } else if double {
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => {
                regex.push_str("[^/]");
                index += 1;
            }
            ch => {
                regex.push_str(&regex::escape(&ch.to_string()));
                index += 1;
            }
        }
    }

    regex.push('$');
    Regex::new(&regex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo(gitignore: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(".gitignore"), gitignore).unwrap();
        temp
    }

    #[test]
    fn matches_a_simple_env_pattern() {
        let repo = temp_repo(".env\n");
        assert!(is_ignored(repo.path(), ".env"));
        assert!(!is_ignored(repo.path(), ".env.example"));
    }

    #[test]
    fn supports_globs_and_negation() {
        let repo = temp_repo(".env*\n!.env.example\n");
        assert!(is_ignored(repo.path(), ".env.local"));
        assert!(!is_ignored(repo.path(), ".env.example"));
    }

    #[test]
    fn supports_directory_patterns() {
        let repo = temp_repo("secrets/\n");
        assert!(is_ignored(repo.path(), "secrets/prod.env"));
        assert!(!is_ignored(repo.path(), "config/prod.env"));
    }

    #[test]
    fn supports_unanchored_basename_patterns() {
        let repo = temp_repo("*.local\n");
        assert!(is_ignored(repo.path(), ".env.local"));
        assert!(is_ignored(repo.path(), "config/.env.local"));
        assert!(!is_ignored(repo.path(), "config/.env"));
    }

    #[test]
    fn supports_anchored_and_path_patterns() {
        let repo = temp_repo("/root.env\nconfig/*.env\n");
        assert!(is_ignored(repo.path(), "root.env"));
        assert!(!is_ignored(repo.path(), "nested/root.env"));
        assert!(is_ignored(repo.path(), "config/prod.env"));
        assert!(!is_ignored(repo.path(), "config/nested/prod.env"));
    }

    #[test]
    fn supports_double_star_patterns() {
        let repo = temp_repo("**/*.local\n");
        assert!(is_ignored(repo.path(), ".env.local"));
        assert!(is_ignored(repo.path(), "a/b/.env.local"));
    }

    #[test]
    fn reads_nested_gitignore_files() {
        let repo = temp_repo("");
        fs::create_dir_all(repo.path().join("config")).unwrap();
        fs::write(repo.path().join("config/.gitignore"), ".env\n").unwrap();
        assert!(is_ignored(repo.path(), "config/.env"));
        assert!(!is_ignored(repo.path(), ".env"));
    }

    #[test]
    fn ignores_comments_and_escaped_markers() {
        let repo = temp_repo("# comment\n\\#literal\n\\!important\n");
        assert!(!is_ignored(repo.path(), ".env"));
        assert!(is_ignored(repo.path(), "#literal"));
        assert!(is_ignored(repo.path(), "!important"));
    }

    #[test]
    fn returns_false_without_a_gitignore() {
        let repo = tempfile::tempdir().unwrap();
        assert!(!is_ignored(repo.path(), ".env"));
    }
}
