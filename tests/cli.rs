use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn repo() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn run(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_envaudit"))
        .current_dir(directory)
        .args(args)
        .env_remove("NO_COLOR")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn missing_repo() -> TempDir {
    let temp = repo();
    write(
        &temp.path().join("src/app.ts"),
        "const region = process.env.DEPLOY_REGION;\n",
    );
    temp
}

#[test]
fn help_and_version_exit_zero() {
    let temp = repo();
    let help = run(temp.path(), &["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    assert!(text.contains("EnvAudit is a local-first CLI"));
    assert!(text.contains("Exit codes:"));
    assert!(text.contains("--fail-on"));

    let version = run(temp.path(), &["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn usage_errors_exit_one_not_two() {
    let temp = repo();

    let missing_command = run(temp.path(), &[]);
    assert_eq!(missing_command.status.code(), Some(1));

    let conflicting = run(temp.path(), &["scan", "--json", "--markdown"]);
    assert_eq!(conflicting.status.code(), Some(1));

    let unknown_flag = run(temp.path(), &["scan", "--not-a-flag"]);
    assert_eq!(unknown_flag.status.code(), Some(1));

    let missing_path = run(temp.path(), &["scan", "does-not-exist"]);
    assert_eq!(missing_path.status.code(), Some(1));
    assert!(stderr(&missing_path).contains("error:"));
}

#[test]
fn default_run_is_report_only_and_exits_zero() {
    let temp = missing_repo();
    let output = run(temp.path(), &["scan", "."]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("missing"));
    assert!(text.contains("DEPLOY_REGION"));
    assert!(text.contains("Result: report only"));
    assert!(!text.contains("\u{1b}["));
}

#[test]
fn fail_on_missing_exits_two() {
    let temp = missing_repo();

    let failing = run(temp.path(), &["scan", ".", "--fail-on", "missing"]);
    assert_eq!(failing.status.code(), Some(2));
    assert!(stdout(&failing).contains("Result: fail"));

    let other_threshold = run(temp.path(), &["scan", ".", "--fail-on", "secret"]);
    assert_eq!(other_threshold.status.code(), Some(0));
    assert!(stdout(&other_threshold).contains("Result: pass"));
}

#[test]
fn secret_failure_redacts_the_value() {
    let temp = repo();
    write(
        &temp.path().join(".env"),
        "STRIPE_SECRET_KEY=64f3b9d1c7a24e6f8b0d5a2c9e1f7b3d\n",
    );

    let output = run(temp.path(), &["scan", ".", "--fail-on", "secret"]);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(text.contains("SECRET"));
    assert!(!text.contains("64f3b9d1c7a24e6f8b0d5a2c9e1f7b3d"));
    let json = run(temp.path(), &["scan", ".", "--json"]);
    assert!(!stdout(&json).contains("64f3b9d1c7a24e6f8b0d5a2c9e1f7b3d"));
}

#[test]
fn any_ignores_information_only_findings() {
    let temp = repo();
    write(&temp.path().join(".env"), "DUPLICATED=one\n");
    write(&temp.path().join(".env.local"), "DUPLICATED=two\n");

    let info_only = run(temp.path(), &["scan", ".", "--fail-on", "any"]);
    assert_eq!(info_only.status.code(), Some(0));
    assert!(stdout(&info_only).contains("duplicate"));

    write(&temp.path().join(".env.example"), "UNUSED_FLAG=true\n");
    let warning = run(temp.path(), &["scan", ".", "--fail-on", "any"]);
    assert_eq!(warning.status.code(), Some(2));
}

#[test]
fn json_output_has_the_documented_shape() {
    let temp = missing_repo();
    let output = run(temp.path(), &["scan", ".", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool"]["name"], "envaudit");
    assert_eq!(value["root"], ".");
    assert_eq!(value["files_scanned"], 1);
    assert_eq!(value["summary"]["total"], 1);
    assert_eq!(value["summary"]["kinds"]["missing"], 1);
    assert_eq!(value["findings"][0]["kind"], "missing");
    assert_eq!(value["findings"][0]["severity"], "error");
    assert_eq!(value["findings"][0]["locations"][0]["path"], "src/app.ts");
    assert_eq!(value["findings"][0]["locations"][0]["role"], "usage");
}

#[test]
fn markdown_output_is_grouped_and_stable() {
    let temp = missing_repo();
    write(&temp.path().join(".env.example"), "UNUSED_FLAG=true\n");
    let output = run(temp.path(), &["scan", ".", "--markdown"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    assert!(text.contains("# EnvAudit report"));
    assert!(text.contains("## Summary"));
    assert!(text.contains("## Error (1)"));
    assert!(text.contains("## Warning (1)"));
    assert!(text.contains("### `DEPLOY_REGION` — missing"));
    assert!(!text.contains("64f3b9d1c7a24e6f8b0d5a2c9e1f7b3d"));
}

#[test]
fn parse_errors_exit_one_with_a_helpful_message() {
    let temp = repo();
    write(&temp.path().join(".env"), "BROKEN LINE\n");
    let output = run(temp.path(), &["scan", ".", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    let text = stderr(&output);
    assert!(text.contains("failed to parse env file `.env`"));
    assert!(text.contains("KEY=VALUE"));
}

#[test]
fn a_file_as_scan_target_is_a_usage_error() {
    let temp = repo();
    write(&temp.path().join("file.txt"), "hello\n");
    let output = run(temp.path(), &["scan", "file.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not a directory"));
}

#[test]
fn no_color_environment_is_respected() {
    let temp = missing_repo();
    let output = Command::new(env!("CARGO_BIN_EXE_envaudit"))
        .current_dir(temp.path())
        .args(["scan", "."])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(!stdout(&output).contains("\u{1b}["));
}

#[test]
fn fixture_expected_outputs_are_current() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("examples/fixture-project");

    let text = run(&fixture, &["scan", "."]);
    assert_eq!(text.status.code(), Some(0));
    let expected_text = fs::read_to_string(root.join("examples/expected-output.txt")).unwrap();
    assert_eq!(stdout(&text), expected_text);

    let json = run(&fixture, &["scan", ".", "--json"]);
    assert_eq!(json.status.code(), Some(0));
    let expected_json = fs::read_to_string(root.join("examples/expected-output.json")).unwrap();
    assert_eq!(stdout(&json), expected_json);
}
