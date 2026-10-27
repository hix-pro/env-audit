use std::fmt;

/// How an env file should be treated by the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnvKind {
    /// A real runtime file such as `.env` or `.env.local`.
    Real,
    /// A checked-in example or template such as `.env.example`.
    Example,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses the dotenv subset commonly accepted by dotenv libraries: comments,
/// `export`, unquoted values, single/double quotes, and trailing comments.
pub fn parse(content: &str) -> Result<Vec<Entry>, ParseError> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut entries = Vec::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let mut line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(after_export) = line.strip_prefix("export") {
            if after_export.chars().next().is_some_and(char::is_whitespace) {
                line = after_export.trim_start();
            }
        }

        let Some(equals) = line.find('=') else {
            return Err(error(line_number, "expected KEY=VALUE"));
        };
        let key = line[..equals].trim();
        if key.is_empty() {
            return Err(error(line_number, "empty variable name"));
        }
        if !is_valid_env_key(key) {
            return Err(error(line_number, format!("invalid variable name `{key}`")));
        }

        let value = parse_value(&line[equals + 1..], line_number)?;
        entries.push(Entry {
            key: key.to_owned(),
            value,
            line: line_number,
        });
    }

    Ok(entries)
}

/// Returns whether a filename is a dotenv file and whether it is an example.
pub fn classify_env_file(name: &str) -> Option<EnvKind> {
    if name == ".envrc" {
        return None;
    }
    if name != ".env" && !name.starts_with(".env.") {
        return None;
    }

    let lower = name.to_ascii_lowercase();
    let is_example = [".example", ".sample", ".template"]
        .iter()
        .any(|marker| lower.contains(marker));
    Some(if is_example {
        EnvKind::Example
    } else {
        EnvKind::Real
    })
}

/// Environment names accepted by the parser. This is intentionally a little
/// wider than shell identifiers because some tools allow dots and dashes.
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

fn parse_value(raw: &str, line: usize) -> Result<String, ParseError> {
    let value = raw.trim_start();
    if let Some(rest) = value.strip_prefix('"') {
        parse_double_quoted(rest, line)
    } else if let Some(rest) = value.strip_prefix('\'') {
        parse_single_quoted(rest, line)
    } else {
        Ok(strip_unquoted_comment(value).trim_end().to_owned())
    }
}

fn parse_double_quoted(rest: &str, line: usize) -> Result<String, ParseError> {
    let mut parsed = String::new();
    let mut chars = rest.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => {
                ensure_only_comment(&rest[index + 1..], line)?;
                return Ok(parsed);
            }
            '\\' => match chars.next() {
                Some((_, 'n')) => parsed.push('\n'),
                Some((_, 'r')) => parsed.push('\r'),
                Some((_, 't')) => parsed.push('\t'),
                Some((_, escaped)) => parsed.push(escaped),
                None => break,
            },
            other => parsed.push(other),
        }
    }

    Err(error(line, "unterminated double-quoted value"))
}

fn parse_single_quoted(rest: &str, line: usize) -> Result<String, ParseError> {
    match rest.find('\'') {
        Some(end) => {
            ensure_only_comment(&rest[end + 1..], line)?;
            Ok(rest[..end].to_owned())
        }
        None => Err(error(line, "unterminated single-quoted value")),
    }
}

fn ensure_only_comment(rest: &str, line: usize) -> Result<(), ParseError> {
    let trailing = rest.trim();
    if trailing.is_empty() || trailing.starts_with('#') {
        Ok(())
    } else {
        Err(error(line, "unexpected characters after closing quote"))
    }
}

fn strip_unquoted_comment(value: &str) -> &str {
    for (index, ch) in value.char_indices() {
        if ch == '#'
            && (index == 0
                || value[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace))
        {
            return &value[..index];
        }
    }
    value
}

fn error(line: usize, message: impl Into<String>) -> ParseError {
    ParseError {
        line,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(content: &str) -> Vec<(String, String, usize)> {
        parse(content)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.key, entry.value, entry.line))
            .collect()
    }

    #[test]
    fn parses_simple_assignments() {
        assert_eq!(
            entries("DATABASE_URL=postgres://localhost/app\nPORT=3000\n"),
            vec![
                ("DATABASE_URL".into(), "postgres://localhost/app".into(), 1),
                ("PORT".into(), "3000".into(), 2),
            ]
        );
    }

    #[test]
    fn ignores_comments_blank_lines_and_export() {
        let content = "# comment\n\n  # indented comment\nexport API_URL=https://example.com\n";
        assert_eq!(
            entries(content),
            vec![("API_URL".into(), "https://example.com".into(), 4)]
        );
    }

    #[test]
    fn parses_quoted_values_and_comments() {
        let content = concat!(
            "DOUBLE=\"hello world\"\n",
            "SINGLE='raw $value # literal'\n",
            "INLINE=value # trailing comment\n",
            "HASH=abc#def\n",
            "ESCAPED=\"line\\nnext \\\"quote\\\"\"\n",
        );
        assert_eq!(
            entries(content),
            vec![
                ("DOUBLE".into(), "hello world".into(), 1),
                ("SINGLE".into(), "raw $value # literal".into(), 2),
                ("INLINE".into(), "value".into(), 3),
                ("HASH".into(), "abc#def".into(), 4),
                ("ESCAPED".into(), "line\nnext \"quote\"".into(), 5),
            ]
        );
    }

    #[test]
    fn parses_empty_values_and_duplicate_keys() {
        let content = "EMPTY=\nDUP=one\nDUP=two\n";
        let parsed = parse(content).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].value, "");
        assert_eq!(parsed[1].value, "one");
        assert_eq!(parsed[2].value, "two");
    }

    #[test]
    fn rejects_lines_without_equals() {
        let error = parse("NOT_AN_ASSIGNMENT\n").unwrap_err();
        assert_eq!(error.line, 1);
        assert!(error.message.contains("KEY=VALUE"));
    }

    #[test]
    fn rejects_invalid_keys() {
        let error = parse("1BAD=value\n").unwrap_err();
        assert!(error.message.contains("invalid variable name"));
    }

    #[test]
    fn rejects_unterminated_quotes() {
        assert!(parse("A=\"unfinished\n").is_err());
        assert!(parse("B='unfinished\n").is_err());
    }

    #[test]
    fn rejects_junk_after_a_closing_quote() {
        assert!(parse("A=\"value\"junk\n").is_err());
    }

    #[test]
    fn handles_crlf_and_bom() {
        let parsed = parse("\u{feff}A=1\r\nB=2\r\n").unwrap();
        assert_eq!(parsed[0].key, "A");
        assert_eq!(parsed[0].value, "1");
        assert_eq!(parsed[1].line, 2);
    }

    #[test]
    fn classifies_env_files() {
        assert_eq!(classify_env_file(".env"), Some(EnvKind::Real));
        assert_eq!(classify_env_file(".env.local"), Some(EnvKind::Real));
        assert_eq!(classify_env_file(".env.production"), Some(EnvKind::Real));
        assert_eq!(classify_env_file(".env.example"), Some(EnvKind::Example));
        assert_eq!(
            classify_env_file(".env.staging.sample"),
            Some(EnvKind::Example)
        );
        assert_eq!(classify_env_file(".env.template"), Some(EnvKind::Example));
        assert_eq!(classify_env_file(".envrc"), None);
        assert_eq!(classify_env_file("environment.env"), None);
        assert_eq!(classify_env_file("app.env"), None);
    }

    #[test]
    fn validates_key_characters() {
        assert!(is_valid_env_key("DATABASE_URL"));
        assert!(is_valid_env_key("_PRIVATE"));
        assert!(is_valid_env_key("APP.ENV"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("9LIVES"));
        assert!(!is_valid_env_key("HAS SPACE"));
    }
}
