use std::fmt;

use crate::dotenv::is_valid_env_key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for YamlError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvKey {
    pub key: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedYaml {
    pub env_keys: Vec<EnvKey>,
    pub env_file_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct YamlLine {
    number: usize,
    indent: usize,
    text: String,
}

/// Extracts environment keys and `env_file` references from Compose YAML. This
/// is a targeted parser, not a general YAML implementation.
pub fn parse_compose(content: &str) -> Result<ParsedYaml, YamlError> {
    parse(content, Mode::Compose)
}

/// Extracts `env:` maps from GitHub Actions workflow YAML.
pub fn parse_workflow(content: &str) -> Result<ParsedYaml, YamlError> {
    parse(content, Mode::Workflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Compose,
    Workflow,
}

fn parse(content: &str, mode: Mode) -> Result<ParsedYaml, YamlError> {
    let lines = prepare(content);
    let mut parsed = ParsedYaml::default();
    let mut skip_until = 0;

    for (index, line) in lines.iter().enumerate() {
        if index < skip_until {
            continue;
        }
        let Some((key, value)) = trigger(line) else {
            continue;
        };
        match (mode, key.as_str()) {
            (Mode::Compose, "environment") => {
                let keys = parse_environment(&lines, index, &value, line.indent)?;
                parsed.env_keys.extend(keys);
                if value.is_empty() {
                    skip_until = block_end(&lines, index, line.indent);
                }
            }
            (Mode::Compose, "env_file") => {
                let paths = parse_env_file(&lines, index, &value, line.indent)?;
                parsed.env_file_paths.extend(paths);
                if value.is_empty() {
                    skip_until = block_end(&lines, index, line.indent);
                }
            }
            (Mode::Workflow, "env") => {
                let keys = parse_workflow_env(&lines, index, &value, line.indent)?;
                parsed.env_keys.extend(keys);
                if value.is_empty() {
                    skip_until = block_end(&lines, index, line.indent);
                }
            }
            _ => {}
        }
    }

    parsed.env_keys.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.key.cmp(&right.key))
    });
    parsed.env_keys.dedup();
    parsed.env_file_paths.sort();
    parsed.env_file_paths.dedup();
    Ok(parsed)
}

fn prepare(content: &str) -> Vec<YamlLine> {
    content
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let raw = raw.trim_end();
            let trimmed = raw.trim_start_matches([' ', '\t']);
            if trimmed.is_empty() {
                return None;
            }
            let indent = raw.len() - trimmed.len();
            let text = strip_comment(trimmed).trim_end().to_owned();
            if text.is_empty() || text == "---" || text == "..." {
                return None;
            }
            Some(YamlLine {
                number: index + 1,
                indent,
                text,
            })
        })
        .collect()
}

fn trigger(line: &YamlLine) -> Option<(String, String)> {
    let candidate = strip_list_marker(&line.text).unwrap_or(&line.text);
    let (key, value) = split_mapping(candidate)?;
    Some((unquote(key), value.trim().to_owned()))
}

fn parse_environment(
    lines: &[YamlLine],
    index: usize,
    value: &str,
    base_indent: usize,
) -> Result<Vec<EnvKey>, YamlError> {
    if !value.is_empty() {
        if value.starts_with('[') {
            let items = parse_inline_sequence(value, lines[index].number)?;
            return items
                .iter()
                .map(|item| environment_list_item(item, lines[index].number))
                .collect();
        }
        if value.starts_with('{') {
            return parse_inline_mapping(value, lines[index].number);
        }
        // Anchors, aliases, and other non-literal forms are intentionally left
        // to a full YAML parser.
        return Ok(Vec::new());
    }

    let block = child_block(lines, index, base_indent);
    let Some(first) = block.first() else {
        return Ok(Vec::new());
    };

    if first.text.trim_start().starts_with('-') {
        let child_indent = first.indent;
        let mut keys = Vec::new();
        for line in block {
            if line.indent < child_indent {
                break;
            }
            if line.indent > child_indent {
                continue;
            }
            let Some(item) = strip_list_marker(&line.text) else {
                break;
            };
            keys.push(environment_list_item(item, line.number)?);
        }
        Ok(keys)
    } else {
        parse_block_mapping(block, first.indent, "environment variable")
    }
}

fn parse_workflow_env(
    lines: &[YamlLine],
    index: usize,
    value: &str,
    base_indent: usize,
) -> Result<Vec<EnvKey>, YamlError> {
    if !value.is_empty() {
        return if value.starts_with('{') {
            parse_inline_mapping(value, lines[index].number)
        } else {
            // Scalar expressions are valid YAML but outside this targeted
            // parser. Ignore them rather than failing an otherwise usable run.
            Ok(Vec::new())
        };
    }

    let block = child_block(lines, index, base_indent);
    let Some(first) = block.first() else {
        return Ok(Vec::new());
    };
    if first.text.trim_start().starts_with('-') {
        return Ok(Vec::new());
    }
    parse_block_mapping(block, first.indent, "environment variable")
}

fn parse_block_mapping(
    block: &[YamlLine],
    child_indent: usize,
    what: &str,
) -> Result<Vec<EnvKey>, YamlError> {
    let mut keys = Vec::new();
    for line in block {
        if line.indent < child_indent {
            break;
        }
        if line.indent > child_indent {
            continue;
        }
        if line.text.trim_start().starts_with('-') {
            break;
        }
        let Some((key, _value)) = split_mapping(&line.text) else {
            return Err(YamlError {
                line: line.number,
                message: format!("expected {what} in the form KEY: value"),
            });
        };
        let key = unquote(key);
        if !is_valid_env_key(&key) {
            return Err(YamlError {
                line: line.number,
                message: format!("invalid {what} name `{key}`"),
            });
        }
        keys.push(EnvKey {
            key,
            line: line.number,
        });
    }
    Ok(keys)
}

fn environment_list_item(item: &str, line: usize) -> Result<EnvKey, YamlError> {
    let item = unquote(item);
    let item = item.trim();
    if item.is_empty() {
        return Err(YamlError {
            line,
            message: "empty environment entry".to_owned(),
        });
    }
    if item.starts_with('{') {
        let entries = parse_inline_mapping(item, line)?;
        return entries.into_iter().next().ok_or_else(|| YamlError {
            line,
            message: "empty environment mapping".to_owned(),
        });
    }

    let key = match split_assignment(item) {
        Some((key, _value)) => unquote(key),
        None => unquote(item),
    };
    if !is_valid_env_key(&key) {
        return Err(YamlError {
            line,
            message: format!("invalid environment variable name `{key}`"),
        });
    }
    Ok(EnvKey { key, line })
}

fn parse_env_file(
    lines: &[YamlLine],
    index: usize,
    value: &str,
    base_indent: usize,
) -> Result<Vec<String>, YamlError> {
    if !value.is_empty() {
        if value.starts_with('[') {
            let items = parse_inline_sequence(value, lines[index].number)?;
            return items
                .iter()
                .map(|item| env_file_item(item, lines[index].number))
                .collect();
        }
        if value.starts_with('{') {
            return Ok(inline_env_file_paths(value, lines[index].number)?
                .into_iter()
                .collect());
        }
        return Ok(vec![unquote(value)]);
    }

    let block = child_block(lines, index, base_indent);
    let Some(first) = block.first() else {
        return Ok(Vec::new());
    };
    let child_indent = first.indent;
    let mut paths = Vec::new();
    for line in block {
        if line.indent < child_indent {
            break;
        }
        if line.indent > child_indent {
            continue;
        }
        let Some(item) = strip_list_marker(&line.text) else {
            // A mapping form (`env_file: {path: .env}`) is handled above.
            break;
        };
        paths.push(env_file_item(item, line.number)?);
    }
    Ok(paths)
}

fn inline_env_file_paths(value: &str, line: usize) -> Result<Vec<String>, YamlError> {
    let inner = delimited(value, '{', '}', line)?;
    let mut paths = Vec::new();
    for item in split_top_level(inner, ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((key, raw_value)) = split_mapping(item) else {
            return Err(YamlError {
                line,
                message: format!("expected `path: FILE` in inline env_file, found `{item}`"),
            });
        };
        if unquote(key) == "path" {
            let path = unquote(raw_value);
            if path.is_empty() {
                return Err(YamlError {
                    line,
                    message: "env_file path is empty".to_owned(),
                });
            }
            paths.push(path);
        }
    }
    Ok(paths)
}

fn env_file_item(item: &str, line: usize) -> Result<String, YamlError> {
    let item = item.trim();
    if item.is_empty() {
        return Err(YamlError {
            line,
            message: "empty env_file entry".to_owned(),
        });
    }
    if item.starts_with('{') {
        let mut paths = inline_env_file_paths(item, line)?;
        return paths.pop().ok_or_else(|| YamlError {
            line,
            message: "env_file mapping is missing a `path`".to_owned(),
        });
    }
    if let Some((key, value)) = split_mapping(item) {
        if unquote(key) == "path" {
            let value = unquote(value);
            if value.is_empty() {
                return Err(YamlError {
                    line,
                    message: "env_file path is empty".to_owned(),
                });
            }
            return Ok(value);
        }
        return Err(YamlError {
            line,
            message: "expected `path: FILE` in env_file entry".to_owned(),
        });
    }
    Ok(unquote(item))
}

fn child_block(lines: &[YamlLine], index: usize, base_indent: usize) -> &[YamlLine] {
    let start = index + 1;
    let end = block_end(lines, index, base_indent);
    &lines[start..end]
}

fn block_end(lines: &[YamlLine], index: usize, base_indent: usize) -> usize {
    let mut end = index + 1;
    while end < lines.len() && lines[end].indent > base_indent {
        end += 1;
    }
    end
}

fn parse_inline_mapping(value: &str, line: usize) -> Result<Vec<EnvKey>, YamlError> {
    let inner = delimited(value, '{', '}', line)?;
    let mut keys = Vec::new();
    for item in split_top_level(inner, ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((key, _value)) = split_mapping(item) else {
            return Err(YamlError {
                line,
                message: format!("expected KEY: value in inline mapping, found `{item}`"),
            });
        };
        let key = unquote(key);
        if !is_valid_env_key(&key) {
            return Err(YamlError {
                line,
                message: format!("invalid environment variable name `{key}`"),
            });
        }
        keys.push(EnvKey { key, line });
    }
    Ok(keys)
}

fn parse_inline_sequence(value: &str, line: usize) -> Result<Vec<String>, YamlError> {
    let inner = delimited(value, '[', ']', line)?;
    Ok(split_top_level(inner, ',')
        .into_iter()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect())
}

fn delimited(value: &str, open: char, close: char, line: usize) -> Result<&str, YamlError> {
    let value = value.trim();
    if !value.starts_with(open) || !value.ends_with(close) {
        return Err(YamlError {
            line,
            message: format!("unterminated inline value `{value}`"),
        });
    }
    Ok(&value[open.len_utf8()..value.len() - close.len_utf8()])
}

fn split_top_level(value: &str, separator: char) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut square = 0_i32;
    let mut curly = 0_i32;

    for (index, ch) in value.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && active == '"' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' => square += 1,
            ']' => square -= 1,
            '{' => curly += 1,
            '}' => curly -= 1,
            c if c == separator && square == 0 && curly == 0 => {
                items.push(&value[start..index]);
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    items.push(&value[start..]);
    items
}

fn split_mapping(value: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut escaped = false;
    let mut square = 0_i32;
    let mut curly = 0_i32;

    for (index, ch) in value.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && active == '"' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' => square += 1,
            ']' => square -= 1,
            '{' => curly += 1,
            '}' => curly -= 1,
            ':' if square == 0 && curly == 0 => {
                let after = value[index + 1..].chars().next();
                if after.is_none() || after.is_some_and(char::is_whitespace) {
                    return Some((value[..index].trim(), value[index + 1..].trim()));
                }
            }
            _ => {}
        }
    }
    None
}

fn split_assignment(value: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && active == '"' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '=' => return Some((value[..index].trim(), value[index + 1..].trim())),
            _ => {}
        }
    }
    None
}

fn strip_list_marker(value: &str) -> Option<&str> {
    let trimmed = value.trim_start();
    let rest = trimmed.strip_prefix('-')?;
    if rest.is_empty() {
        Some("")
    } else if rest.starts_with(char::is_whitespace) {
        Some(rest.trim_start())
    } else {
        None
    }
}

fn strip_comment(value: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && active == '"' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '#' if index == 0
                || value[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace) =>
            {
                return &value[..index];
            }
            _ => {}
        }
    }
    value
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(parsed: &ParsedYaml) -> Vec<&str> {
        parsed
            .env_keys
            .iter()
            .map(|entry| entry.key.as_str())
            .collect()
    }

    #[test]
    fn parses_compose_environment_map_and_env_file_list() {
        let yaml = concat!(
            "services:\n",
            "  api:\n",
            "    environment:\n",
            "      DATABASE_URL: ${DATABASE_URL}\n",
            "      REDIS_URL: ${REDIS_URL:-redis://localhost:6379}\n",
            "    env_file:\n",
            "      - .env\n",
            "      - path: .env.production\n",
            "        required: false\n",
        );
        let parsed = parse_compose(yaml).unwrap();
        assert_eq!(keys(&parsed), vec!["DATABASE_URL", "REDIS_URL"]);
        assert_eq!(
            parsed.env_file_paths,
            vec![".env".to_owned(), ".env.production".to_owned()]
        );
    }

    #[test]
    fn parses_compose_environment_sequence() {
        let yaml = concat!(
            "services:\n",
            "  api:\n",
            "    environment:\n",
            "      - NODE_ENV=production\n",
            "      - FEATURE_CHECKOUT\n",
            "      - \"TOKEN=abc=def\"\n",
        );
        let parsed = parse_compose(yaml).unwrap();
        assert_eq!(keys(&parsed), vec!["NODE_ENV", "FEATURE_CHECKOUT", "TOKEN"]);
    }

    #[test]
    fn parses_inline_environment_forms() {
        let list = "services:\n  api:\n    environment: [A=1, B, 'C=three']\n";
        assert_eq!(keys(&parse_compose(list).unwrap()), vec!["A", "B", "C"]);

        let map = "services:\n  api:\n    environment: {DATABASE_URL: x, \"PORT\": 3000}\n";
        assert_eq!(
            keys(&parse_compose(map).unwrap()),
            vec!["DATABASE_URL", "PORT"]
        );
    }

    #[test]
    fn parses_scalar_inline_env_file() {
        let parsed = parse_compose("services:\n  api:\n    env_file: .env\n").unwrap();
        assert_eq!(parsed.env_file_paths, vec![".env"]);
    }

    #[test]
    fn parses_workflow_env_maps_at_multiple_levels() {
        let yaml = concat!(
            "name: CI\n",
            "env:\n",
            "  NODE_ENV: test\n",
            "jobs:\n",
            "  test:\n",
            "    env:\n",
            "      DATABASE_URL: ${{ secrets.DATABASE_URL }}\n",
            "    steps:\n",
            "      - name: Test\n",
            "        env:\n",
            "          FEATURE_CHECKOUT: \"true\"\n",
            "        run: npm test\n",
        );
        let parsed = parse_workflow(yaml).unwrap();
        assert_eq!(
            keys(&parsed),
            vec!["NODE_ENV", "DATABASE_URL", "FEATURE_CHECKOUT"]
        );
    }

    #[test]
    fn ignores_comments_and_hash_values() {
        let yaml = concat!(
            "services:\n",
            "  api:\n",
            "    environment:\n",
            "      # comment: ignored\n",
            "      PASSWORD: \"abc#123\" # real value\n",
            "      URL: https://example.com/#fragment\n",
        );
        let parsed = parse_compose(yaml).unwrap();
        assert_eq!(keys(&parsed), vec!["PASSWORD", "URL"]);
    }

    #[test]
    fn does_not_parse_unrelated_yaml() {
        let yaml = "name: app\nvariables:\n  FOO: bar\nrun: echo $FOO\n";
        assert!(parse_workflow(yaml).unwrap().env_keys.is_empty());
        assert!(parse_compose(yaml).unwrap().env_keys.is_empty());
    }

    #[test]
    fn reports_malformed_environment_entries() {
        let yaml = "services:\n  api:\n    environment:\n      not a mapping\n";
        let error = parse_compose(yaml).unwrap_err();
        assert_eq!(error.line, 4);
    }

    #[test]
    fn reports_unterminated_inline_sequence() {
        let yaml = "services:\n  api:\n    environment: [A=1\n";
        assert!(parse_compose(yaml).is_err());
    }

    #[test]
    fn leaves_anchor_aliases_alone() {
        let yaml = "services:\n  api:\n    environment: *shared\n";
        assert!(parse_compose(yaml).unwrap().env_keys.is_empty());
    }

    #[test]
    fn ignores_unsupported_workflow_env_forms() {
        let scalar = parse_workflow("env: ${{ fromJSON(needs.setup.outputs.env) }}\n").unwrap();
        assert!(scalar.env_keys.is_empty());
        let sequence = parse_workflow("env:\n  - NOT_A_MAPPING\n").unwrap();
        assert!(sequence.env_keys.is_empty());
    }

    #[test]
    fn captures_line_numbers() {
        let yaml = "env:\n  TOP: 1\njobs:\n  x:\n    env:\n      INNER: 2\n";
        let parsed = parse_workflow(yaml).unwrap();
        assert_eq!(parsed.env_keys[0].line, 2);
        assert_eq!(parsed.env_keys[1].line, 6);
    }
}
