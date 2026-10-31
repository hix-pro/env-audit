use std::collections::BTreeSet;

use tree_sitter::{Node, Parser};

use crate::patterns::{Language, Usage};

/// Parses JavaScript, TypeScript, TSX, and Python with tree-sitter and extracts
/// static environment variable references. The regex scanner stays for Rust,
/// Go, and shell, where the access forms are simple and a parser would add
/// more weight than value.
pub fn scan_language(language: Language, source: &str) -> Vec<Usage> {
    let grammar = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust | Language::Go | Language::Shell => return Vec::new(),
    };

    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut hits = BTreeSet::new();
    match language {
        Language::Python => {
            let context = PythonContext::collect(tree.root_node(), source);
            walk_python(tree.root_node(), source, &context, &mut hits);
        }
        Language::JavaScript | Language::TypeScript | Language::Tsx => {
            walk_javascript(tree.root_node(), source, &mut hits);
        }
        Language::Rust | Language::Go | Language::Shell => {}
    }
    into_usage(hits)
}

fn into_usage(hits: BTreeSet<(usize, String)>) -> Vec<Usage> {
    hits.into_iter()
        .map(|(line, name)| Usage { name, line })
        .collect()
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn line(node: Node) -> usize {
    node.start_position().row + 1
}

fn env_name(value: &str) -> Option<String> {
    let mut bytes = value.bytes();
    let first = bytes.next()?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return None;
    }
    Some(value.to_owned())
}

fn add(hits: &mut BTreeSet<(usize, String)>, node: Node, value: &str) {
    if let Some(name) = env_name(value) {
        hits.insert((line(node), name));
    }
}

// JavaScript / TypeScript -------------------------------------------------

fn walk_javascript(node: Node, source: &str, hits: &mut BTreeSet<(usize, String)>) {
    match node.kind() {
        "member_expression" => {
            if let Some(name) = javascript_member_name(node, source) {
                add(hits, node, &name);
            }
        }
        "subscript_expression" => {
            if let Some(name) = javascript_subscript_name(node, source) {
                add(hits, node, &name);
            }
        }
        "call_expression" => {
            if let Some(name) = javascript_call_name(node, source) {
                add(hits, node, &name);
            }
        }
        "variable_declarator" => {
            if let (Some(pattern), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                if is_javascript_env_object(value, source) {
                    extract_javascript_pattern(pattern, source, hits);
                }
            }
        }
        "assignment_expression" | "assignment_pattern" => {
            if let (Some(pattern), Some(value)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if pattern.kind() == "object_pattern" && is_javascript_env_object(value, source) {
                    extract_javascript_pattern(pattern, source, hits);
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_javascript(child, source, hits);
    }
}

fn javascript_member_name(node: Node, source: &str) -> Option<String> {
    let object = node.child_by_field_name("object")?;
    if !is_javascript_env_object(object, source) {
        return None;
    }
    let property = node.child_by_field_name("property")?;
    if property.kind() != "property_identifier" {
        return None;
    }
    Some(text(property, source).to_owned())
}

fn javascript_subscript_name(node: Node, source: &str) -> Option<String> {
    let object = node.child_by_field_name("object")?;
    if !is_javascript_env_object(object, source) {
        return None;
    }
    let index = node.child_by_field_name("index")?;
    constant_string(index, source)
}

fn javascript_call_name(node: Node, source: &str) -> Option<String> {
    let function = unwrap_javascript(node.child_by_field_name("function")?);
    if function.kind() != "member_expression" {
        return None;
    }
    let property = function.child_by_field_name("property")?;
    if text(property, source) != "get" {
        return None;
    }
    if !is_deno_env(function.child_by_field_name("object")?, source) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    constant_string(arguments.named_child(0)?, source)
}

fn is_javascript_env_object(node: Node, source: &str) -> bool {
    let node = unwrap_javascript(node);
    match node.kind() {
        "member_expression" => {
            let Some(property) = node.child_by_field_name("property") else {
                return false;
            };
            if text(property, source) != "env" {
                return false;
            }
            let Some(object) = node.child_by_field_name("object") else {
                return false;
            };
            match object.kind() {
                "identifier" => matches!(text(object, source), "process" | "Bun"),
                "meta_property" => text(object, source) == "import.meta",
                _ => false,
            }
        }
        "subscript_expression" => {
            let Some(object) = node.child_by_field_name("object") else {
                return false;
            };
            if !matches!(text(object, source), "process" | "Bun") {
                return false;
            }
            let Some(index) = node.child_by_field_name("index") else {
                return false;
            };
            constant_string(index, source).as_deref() == Some("env")
        }
        _ => false,
    }
}

fn is_deno_env(node: Node, source: &str) -> bool {
    let node = unwrap_javascript(node);
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    text(object, source) == "Deno" && text(property, source) == "env"
}

fn unwrap_javascript(mut node: Node) -> Node {
    loop {
        let next = match node.kind() {
            "parenthesized_expression"
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression" => node.named_child(0),
            "type_assertion" => node
                .child_by_field_name("expression")
                .or_else(|| node.named_child(1)),
            _ => None,
        };
        match next {
            Some(inner) => node = inner,
            None => return node,
        }
    }
}

fn extract_javascript_pattern(pattern: Node, source: &str, hits: &mut BTreeSet<(usize, String)>) {
    if pattern.kind() != "object_pattern" {
        return;
    }
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier_pattern" => add(hits, child, text(child, source)),
            "object_assignment_pattern" => {
                if let Some(left) = child.child_by_field_name("left") {
                    add(hits, left, text(left, source));
                }
            }
            "pair_pattern" => {
                if let Some(key) = child.child_by_field_name("key") {
                    if let Some(name) = javascript_pattern_key(key, source) {
                        add(hits, key, &name);
                    }
                }
            }
            _ => {}
        }
    }
}

fn javascript_pattern_key(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" => Some(text(node, source).to_owned()),
        "string" => constant_string(node, source),
        "computed_property_name" => constant_string(node.named_child(0)?, source),
        _ => None,
    }
}

fn constant_string(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "string" => string_value(node, source),
        "template_string" => {
            if has_child_kind(node, "template_substitution") {
                return None;
            }
            string_value(node, source)
        }
        "concatenated_string" => {
            let mut value = String::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                value.push_str(&constant_string(child, source)?);
            }
            Some(value)
        }
        "parenthesized_expression" => constant_string(node.named_child(0)?, source),
        _ => None,
    }
}

fn string_value(node: Node, source: &str) -> Option<String> {
    if has_child_kind(node, "escape_sequence") || has_child_kind(node, "interpolation") {
        return None;
    }
    if node.kind() == "string" {
        if let Some(start) = node.child(0) {
            let prefix = text(start, source).to_ascii_lowercase();
            if prefix.contains('b') {
                return None;
            }
        }
    }
    let mut value = String::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "string_fragment" | "string_content") {
            value.push_str(text(child, source));
        }
    }
    if value.is_empty() { None } else { Some(value) }
}

fn has_child_kind(node: Node, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

// Python -----------------------------------------------------------------

#[derive(Debug, Default)]
struct PythonContext {
    os_aliases: BTreeSet<String>,
    environ_aliases: BTreeSet<String>,
    getenv_aliases: BTreeSet<String>,
}

impl PythonContext {
    fn collect(root: Node, source: &str) -> Self {
        let mut context = Self::default();
        context.os_aliases.insert("os".to_owned());
        collect_python_imports(root, source, &mut context);
        context
    }
}

fn collect_python_imports(node: Node, source: &str, context: &mut PythonContext) {
    match node.kind() {
        "import_statement" => {
            let mut cursor = node.walk();
            for (index, child) in node.children(&mut cursor).enumerate() {
                if node.field_name_for_child(index as u32) != Some("name") {
                    continue;
                }
                match child.kind() {
                    "dotted_name" => {
                        let module = text(child, source);
                        if module == "os" || module.starts_with("os.") {
                            context.os_aliases.insert("os".to_owned());
                        }
                    }
                    "aliased_import" => {
                        let Some(name) = child.child_by_field_name("name") else {
                            continue;
                        };
                        let Some(alias) = child.child_by_field_name("alias") else {
                            continue;
                        };
                        if text(name, source) == "os" {
                            context.os_aliases.insert(text(alias, source).to_owned());
                        }
                    }
                    _ => {}
                }
            }
        }
        "import_from_statement" => {
            let Some(module) = node.child_by_field_name("module_name") else {
                return;
            };
            if text(module, source) != "os" {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    collect_python_imports(child, source, context);
                }
                return;
            }
            let mut cursor = node.walk();
            for (index, child) in node.children(&mut cursor).enumerate() {
                if node.field_name_for_child(index as u32) != Some("name") {
                    continue;
                }
                match child.kind() {
                    "dotted_name" => {
                        let name = text(child, source);
                        match name {
                            "environ" => {
                                context.environ_aliases.insert("environ".to_owned());
                            }
                            "getenv" => {
                                context.getenv_aliases.insert("getenv".to_owned());
                            }
                            "*" => {
                                context.environ_aliases.insert("environ".to_owned());
                                context.getenv_aliases.insert("getenv".to_owned());
                            }
                            _ => {}
                        }
                    }
                    "aliased_import" => {
                        let Some(name) = child.child_by_field_name("name") else {
                            continue;
                        };
                        let Some(alias) = child.child_by_field_name("alias") else {
                            continue;
                        };
                        match text(name, source) {
                            "environ" => {
                                context
                                    .environ_aliases
                                    .insert(text(alias, source).to_owned());
                            }
                            "getenv" => {
                                context
                                    .getenv_aliases
                                    .insert(text(alias, source).to_owned());
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_imports(child, source, context);
    }
}

fn walk_python(
    node: Node,
    source: &str,
    context: &PythonContext,
    hits: &mut BTreeSet<(usize, String)>,
) {
    match node.kind() {
        "subscript" => {
            if let Some(name) = python_subscript_name(node, source, context) {
                add(hits, node, &name);
            }
        }
        "call" => {
            if let Some(name) = python_call_name(node, source, context) {
                add(hits, node, &name);
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_python(child, source, context, hits);
    }
}

fn python_subscript_name(node: Node, source: &str, context: &PythonContext) -> Option<String> {
    if !is_python_environ(node.child_by_field_name("value")?, source, context) {
        return None;
    }
    constant_string(node.child_by_field_name("subscript")?, source)
}

fn python_call_name(node: Node, source: &str, context: &PythonContext) -> Option<String> {
    let function = unwrap_python(node.child_by_field_name("function")?);
    let is_env_call = match function.kind() {
        "attribute" => {
            let attribute = function.child_by_field_name("attribute")?;
            let name = text(attribute, source);
            if matches!(name, "get" | "setdefault" | "pop") {
                is_python_environ(function.child_by_field_name("object")?, source, context)
            } else if name == "getenv" {
                is_python_os_object(function.child_by_field_name("object")?, source, context)
            } else {
                false
            }
        }
        "identifier" => context.getenv_aliases.contains(text(function, source)),
        _ => false,
    };
    if !is_env_call {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    constant_string(arguments.named_child(0)?, source)
}

fn is_python_environ(node: Node, source: &str, context: &PythonContext) -> bool {
    let node = unwrap_python(node);
    match node.kind() {
        "attribute" => {
            let Some(object) = node.child_by_field_name("object") else {
                return false;
            };
            let Some(attribute) = node.child_by_field_name("attribute") else {
                return false;
            };
            is_python_os_object(object, source, context) && text(attribute, source) == "environ"
        }
        "identifier" => context.environ_aliases.contains(text(node, source)),
        _ => false,
    }
}

fn is_python_os_object(node: Node, source: &str, context: &PythonContext) -> bool {
    let node = unwrap_python(node);
    node.kind() == "identifier" && context.os_aliases.contains(text(node, source))
}

fn unwrap_python(mut node: Node) -> Node {
    loop {
        let next = match node.kind() {
            "parenthesized_expression" => node.named_child(0),
            _ => None,
        };
        match next {
            Some(inner) => node = inner,
            None => return node,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(usages: &[Usage]) -> Vec<&str> {
        usages.iter().map(|usage| usage.name.as_str()).collect()
    }

    fn javascript(source: &str) -> Vec<Usage> {
        scan_language(Language::JavaScript, source)
    }

    fn typescript(source: &str) -> Vec<Usage> {
        scan_language(Language::TypeScript, source)
    }

    fn python(source: &str) -> Vec<Usage> {
        scan_language(Language::Python, source)
    }

    #[test]
    fn finds_javascript_access_forms() {
        let source = concat!(
            "const a = process.env.ALPHA;\n",
            "const b = process.env[\"BRAVO\"];\n",
            "const c = process.env['CHARLIE'];\n",
            "const d = process.env?.DELTA;\n",
            "const e = import.meta.env.ECHO;\n",
            "const f = Bun.env.FOXTROT;\n",
            "const g = Deno.env.get(\"GOLF\");\n",
        );
        let found = javascript(source);
        assert_eq!(
            names(&found),
            vec![
                "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF"
            ]
        );
    }

    #[test]
    fn finds_destructured_javascript_names() {
        let source = concat!(
            "const { ALPHA, BRAVO: b, CHARLIE = 'x', ['DELTA']: d, ...rest } = process.env;\n",
            "({ ECHO } = process.env);\n",
            "function configure({ FOXTROT } = process.env) {}\n",
        );
        let found = javascript(source);
        assert_eq!(
            names(&found),
            vec!["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT"]
        );
    }

    #[test]
    fn finds_typescript_wrapped_env_objects() {
        let source = concat!(
            "const a = (process.env as NodeJS.ProcessEnv).ALPHA;\n",
            "const b = (process.env satisfies Record<string, string>).BRAVO;\n",
            "const c = process.env![\"CHARLIE\"]!;\n",
        );
        let found = typescript(source);
        assert_eq!(names(&found), vec!["ALPHA", "BRAVO", "CHARLIE"]);
    }

    #[test]
    fn ignores_comments_strings_and_dynamic_keys() {
        let source = concat!(
            "// process.env.COMMENT\n",
            "const a = 'process.env.STRING';\n",
            "const b = `process.env.TEMPLATE`;\n",
            "const c = process.env[key];\n",
            "const d = process.env[`DYNAMIC_${key}`];\n",
            "const e = process.env[\"STATIC\"];\n",
        );
        let found = javascript(source);
        assert_eq!(names(&found), vec!["STATIC"]);
    }

    #[test]
    fn finds_template_expressions_but_not_template_text() {
        let source = "const a = `${process.env.ALPHA}`;\nconst b = `process.env.BRAVO`;\n";
        let found = javascript(source);
        assert_eq!(names(&found), vec!["ALPHA"]);
    }

    #[test]
    fn finds_python_environ_access_forms() {
        let source = concat!(
            "import os\n",
            "from os import environ, getenv\n",
            "from os import environ as env, getenv as get_env\n",
            "A = os.environ[\"ALPHA\"]\n",
            "B = os.environ.get('BRAVO')\n",
            "C = os.getenv(\"CHARLIE\")\n",
            "D = environ[\"DELTA\"]\n",
            "E = getenv(\"ECHO\")\n",
            "F = env[\"FOXTROT\"]\n",
            "G = get_env(\"GOLF\")\n",
            "H = os.environ.setdefault(\"HOTEL\", \"x\")\n",
            "I = os.environ.pop(\"INDIA\", None)\n",
        );
        let found = python(source);
        assert_eq!(
            names(&found),
            vec![
                "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL", "INDIA"
            ]
        );
    }

    #[test]
    fn ignores_python_comments_strings_and_dynamic_keys() {
        let source = concat!(
            "# os.environ[\"COMMENT\"]\n",
            "A = \"os.environ['STRING']\"\n",
            "B = os.environ[f\"DYNAMIC_{key}\"]\n",
            "C = os.environ[\"STATIC\"]\n",
        );
        let found = python(source);
        assert_eq!(names(&found), vec!["STATIC"]);
    }

    #[test]
    fn finds_python_import_aliases() {
        let source = concat!(
            "import os as operating_system\n",
            "from os import environ as environment\n",
            "A = operating_system.environ['ALPHA']\n",
            "B = environment['BRAVO']\n",
        );
        let found = python(source);
        assert_eq!(names(&found), vec!["ALPHA", "BRAVO"]);
    }

    #[test]
    fn recovers_from_parse_errors() {
        let found = javascript("const broken = ; process.env.AFTER;");
        assert_eq!(names(&found), vec!["AFTER"]);
    }

    #[test]
    fn leaves_other_languages_to_the_regex_scanner() {
        assert!(scan_language(Language::Rust, "process.env.NOPE").is_empty());
    }
}
