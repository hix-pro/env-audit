# EnvAudit

**Find env vars that are missing, undocumented, unused, or hiding a secret.**

[![CI](https://github.com/hix-pro/env-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/hix-pro/env-audit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hix-pro/env-audit)](https://github.com/hix-pro/env-audit/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

EnvAudit is a local-first Rust CLI that finds environment variables a repository uses but never documents, documents but never uses, and secrets that should not be committed.

It scans JavaScript/TypeScript, Rust, Go, shell, Docker Compose, and GitHub Actions files, then compares what it finds against `.env` files and example templates. It has no network access, no configuration file, and no auto-fix.

## Install

EnvAudit requires Rust 1.85 or newer (Rust 2024 edition).

```console
$ git clone https://github.com/hix-pro/env-audit.git
$ cd env-audit
$ cargo install --path . --locked
```

Or grab a prebuilt binary — every version ships tarballs for Linux x86_64 (gnu), macOS (Apple Silicon), and Windows x86_64, each with a SHA-256 checksum:

```console
$ curl -LO https://github.com/hix-pro/env-audit/releases/latest/download/envaudit-x86_64-unknown-linux-gnu.tar.gz
$ tar xzf envaudit-x86_64-unknown-linux-gnu.tar.gz
$ install envaudit-x86_64-unknown-linux-gnu/envaudit /usr/local/bin/
```

For a local release build without installing:

```console
$ cargo build --release
$ ./target/release/envaudit scan .
```

The repository includes [`examples/fixture-project`](examples/fixture-project), a deliberately broken project used by the example below.

## Usage

```text
envaudit scan [PATH] [--json | --markdown | --sarif] [--fail-on any|missing|secret]
```

`PATH` defaults to `.`. The default mode is a report: findings are printed, but the exit code stays `0` unless a `--fail-on` threshold is supplied.

```console
$ cd examples/fixture-project
$ envaudit scan .
EnvAudit · 0.3.1
Scanned 7 files under .

critical (1)
  secret        STRIPE_SECRET_KEY
    found in .env:3
    A likely secret value is stored in .env, which is not ignored by .gitignore.
    fix: Remove the value from .env, rotate the credential, and add .env to .gitignore.

error (1)
  missing       DEPLOY_REGION
    used at src/server.ts:8
    Referenced in scanned code but not declared in any env file, Compose environment, or workflow env map.
    fix: Add DEPLOY_REGION to .env.example and the deployment environment, or remove the reference.

warning (2)
  undocumented  LEGACY_SMTP_HOST
    declared at .env:4
    Set in runtime configuration but absent from the example env file.
    fix: Add LEGACY_SMTP_HOST to .env.example so new contributors can discover it.
  unused        UNUSED_LEGACY_FLAG
    declared at .env.example:8
    Declared in an example env file but never referenced in scanned code.
    fix: Remove UNUSED_LEGACY_FLAG from the example file or add the code that reads it.

info (1)
  duplicate     DATABASE_URL
    declared at:
      .env:1
      .env.local:1
    Declared with different values across real env files.
    fix: Keep one source of truth, or document the override intentionally.

Summary: 1 critical, 1 error, 2 warnings, 1 info (5 findings)
Result: report only (use --fail-on any|missing|secret to gate CI)
```

The matching expected outputs are committed as [`examples/expected-output.txt`](examples/expected-output.txt) and [`examples/expected-output.json`](examples/expected-output.json).

Text output is colorized only when stdout is a terminal. Set `NO_COLOR` (any value) or `TERM=dumb` to disable color. JSON, Markdown, and SARIF output never contain ANSI escapes.

### SARIF and code scanning

`--sarif` emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document for GitHub code scanning and other SARIF consumers:

```bash
envaudit scan . --sarif > envaudit.sarif
```

Rules are stable (`envaudit/missing`, `envaudit/unused`, `envaudit/undocumented`, `envaudit/secret`, `envaudit/duplicate`). Severity maps to SARIF levels: critical/error → `error`, warning → `warning`, info → `note`. Each result points at the finding's file and line, relative to the repository root. When the scan target is a subdirectory, that prefix is included so annotations still resolve.

Upload it in a workflow with `security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - run: cargo install --git https://github.com/hix-pro/env-audit --locked
  - run: envaudit scan . --sarif > envaudit.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: envaudit.sarif
      category: envaudit
```

The composite action below does this automatically when `sarif: true`.

## Findings

| Kind | Severity | Meaning |
| --- | --- | --- |
| `missing` | error | Used in scanned code or YAML, but not declared in any env file, Compose `environment`, or workflow `env` map. |
| `unused` | warning | Declared in an example/template env file, but never referenced in scanned code or supported YAML. |
| `undocumented` | warning | Declared in a real env file, Compose file, or workflow, but absent from the example env files. Only reported when at least one example file exists. |
| `secret` | critical when the file is not ignored by `.gitignore`, warning when it is | A real env file contains a secret-looking key with a real-looking value. Values are always redacted. |
| `duplicate` | info | The same variable is declared more than once across real env files, or with conflicting values. Values are never printed. |

Findings are sorted by severity (`critical`, `error`, `warning`, `info`), then variable name, kind, message, and locations. A variable can appear in more than one finding if, for example, it is both undeclared and used.

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and no failure threshold was matched. Findings may still exist in report-only mode. |
| `1` | Usage, I/O, or parse error. Invalid CLI arguments also exit `1`. |
| `2` | At least one finding matched `--fail-on`. |

`--fail-on any` matches every finding except informational `duplicate` findings. `--fail-on missing` matches only `missing`; `--fail-on secret` matches only `secret` (whether the secret file is gitignored or not).

## What is detected

| Source | Patterns |
| --- | --- |
| JavaScript / TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`) | `process.env.NAME`, `process.env["NAME"]`, `process.env['NAME']`, `import.meta.env.NAME`, `Bun.env.NAME`, `Deno.env.get("NAME")` |
| Rust (`.rs`) | `env::var("NAME")`, `std::env::var("NAME")`, plus the `_os` variants |
| Go (`.go`) | `os.Getenv("NAME")`, `os.LookupEnv("NAME")` |
| Shell (`.sh`, `.bash`, `.zsh`, `.ksh`, `.dash`) | `$NAME`, `${NAME}`, and `${NAME:-default}`-style operators (`:-`, `-`, `:=`, `=`, `:+`, `+`, `:?`, `?`) |
| Compose and GitHub Actions YAML | `${NAME}` and `${NAME:-default}` interpolations, plus declarations from environment maps |
| Dotenv | Keys declared in `.env`, `.env.*` (except `.envrc`), and files referenced by Compose `env_file` |

Declarations are collected from:

- `.env` files. Names containing `.example`, `.sample`, or `.template` are treated as examples/templates; the rest are treated as real configuration.
- Compose files whose name is `compose.yml`, `compose.yaml`, `docker-compose.yml`, `docker-compose.yaml`, or starts with `compose.` or `docker-compose.` (for example `compose.ci.yaml`), including `services.*.environment` as a map or sequence. `env_file` references are followed inside the scan root.
- GitHub workflow files under `.github/workflows/`, including top-level, job-level, and step-level `env:` maps.

Compose and workflow env maps count as declarations for `missing` and `undocumented` detection. YAML interpolations count as usages. GitHub expression syntax such as `${{ env.NAME }}` is not interpreted as usage.

## Ignored and skipped files

EnvAudit does not enter `.git`, `node_modules`, `target`, `dist`, `build`, `.next`, `coverage`, or `vendor`. It skips lockfiles, files larger than 1 MiB, binary files (NUL bytes), non-UTF-8 files, and symlinks. Symlinks are never followed. Compose `env_file` references outside the scan root are ignored.

Only the source extensions listed above are parsed as code. A shell script without a recognized extension will not be scanned, even if it has a shebang.

## JSON output

`--json` emits a stable, pretty-printed document with `schema_version: 1`. Fields are listed in a fixed order and findings are deterministically sorted.

```json
{
  "schema_version": 1,
  "tool": {
    "name": "envaudit",
    "version": "0.3.1"
  },
  "root": ".",
  "files_scanned": 7,
  "summary": {
    "total": 1,
    "critical": 0,
    "error": 1,
    "warning": 0,
    "info": 0,
    "kinds": {
      "missing": 1,
      "unused": 0,
      "undocumented": 0,
      "secret": 0,
      "duplicate": 0
    }
  },
  "findings": [
    {
      "kind": "missing",
      "severity": "error",
      "variable": "DEPLOY_REGION",
      "summary": "Referenced in scanned code but not declared in any env file, Compose environment, or workflow env map.",
      "fix": "Add DEPLOY_REGION to .env.example and the deployment environment, or remove the reference.",
      "locations": [
        {
          "path": "src/server.ts",
          "line": 8,
          "role": "usage"
        }
      ]
    }
  ]
}
```

Schema notes:

- `root` is the path exactly as passed to `scan` (for example `.` or `services/api`), not an absolute path.
- `files_scanned` counts candidate source, env, Compose, and workflow files discovered by the directory walk after filtering. It does not count `.gitignore` files or env files reached only through Compose `env_file`.
- `summary.kinds` always contains all five keys, including zeros.
- `kind` is one of `missing`, `unused`, `undocumented`, `secret`, `duplicate`.
- `severity` is one of `critical`, `error`, `warning`, `info`.
- Each location has a `path` relative to the scan root, an optional `line`, and a `role` of `usage`, `declaration`, or `secret`.
- `gitignored` is present only on `secret` findings. It reflects the `.gitignore` heuristic, not whether Git actually tracks the file.
- Secret values are never serialized.

`--markdown` emits a deterministic report that starts with `# EnvAudit report`, includes a severity summary table, and groups findings under `## Critical`, `## Error`, `## Warning`, and `## Info` headings. Each finding lists its kind, variable, locations, explanation, and suggested fix. It is suitable for pull request comments without post-processing.

## GitHub Action

The repository ships a composite action that installs EnvAudit and runs it against your workspace — no Rust setup in your workflow:

```yaml
- uses: hix-pro/env-audit@main
  with:
    path: .
    fail-on: any
```

Inputs: `path` (default `.`), `fail-on` (`any`, `missing`, `secret`, or empty for report-only), `args` for extra CLI flags, `sarif` (default `true`), and `category` (default `envaudit`). With `sarif: true`, the action writes a SARIF report, uploads it for code scanning, and preserves the scan's exit code. The caller needs `security-events: write` for the upload; if the permission is missing, the upload is skipped and the scan result still stands.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: hix-pro/env-audit@main
    with:
      path: .
      fail-on: any
```

The SARIF support in this section is on `main` until the next tagged release; pin that tag when it is published. The first run compiles the tool from source, which takes roughly a minute. The repository's own pipeline runs the action against `src` in its Dogfood workflow.

## CI

```yaml
name: EnvAudit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install EnvAudit
        run: cargo install --git https://github.com/hix-pro/env-audit --locked
      - name: Audit environment variables
        run: envaudit scan . --fail-on any
```

Pin `--rev <commit>` on the `cargo install` command if you want reproducible installs.

## How it works

1. `scan` walks the tree with `walkdir`, applies the ignore/size/binary filters, and reads only relevant files.
2. `patterns` applies language-specific regular expressions. `yaml` contains a targeted, indentation-aware parser for Compose environment sections and GitHub `env:` maps; it also collects `${NAME}` interpolations.
3. `dotenv` parses the dotenv subset described below, including comments, `export`, quoted values, and inline comments.
4. `declarations` merges dotenv, Compose, workflow, and referenced `env_file` declarations. `analyze` compares usage against examples and real configuration, applies secret heuristics, and checks `.gitignore`.
5. `report` renders terminal, JSON, or Markdown output. Findings never carry raw dotenv values into a report.

The implementation lives in `src/` with one module per stage (`scan`, `patterns`, `dotenv`, `yaml`, `declarations`, `analyze`, `report`), plus `cli` and `main`.

## Limitations

- Detection is regex-based, not AST-based. Usages in comments or strings can produce false positives, and dynamic access such as `process.env[name]` or destructuring like `const { NAME } = process.env` is not detected. Shell local variables and standard variables can also be reported as missing.
- The YAML parser is deliberately targeted. It does not implement the full YAML specification; anchors, aliases, advanced flow styles, and interpolated `env_file` paths are ignored or unsupported. Only Compose and GitHub Actions YAML are parsed.
- Secret detection is heuristic. It checks real dotenv files only, using key-name and value-shape rules; it is not an entropy scanner or a replacement for provider-specific secret scanning. Placeholder values can be misclassified, and some real secrets will be missed.
- `.gitignore` handling supports the common pattern subset (globs, negation, directory patterns, anchoring, and `**`), but it is not a complete Git implementation. EnvAudit does not inspect the Git index, `.git/info/exclude`, or global excludes, so `gitignored` is only a heuristic.
- The dotenv parser requires `KEY=VALUE` lines, supports single-line quoted values, and only understands basic escape sequences. Malformed lines cause exit code `1`.
- Only files up to 1 MiB are inspected, symlinks are skipped, and only the supported extensions and file names are parsed.
- Example files anywhere under the scan root are pooled as one documentation baseline. In a monorepo with independent services, scan each service directory separately to keep examples and duplicate declarations scoped correctly.
- There is no auto-fix, environment expansion, network lookup, or secret rotation.

## Development

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test --all-targets
$ cargo build --release
$ cargo run -- scan examples/fixture-project
```

Regenerate the committed fixture output from the repository root:

```console
$ cd examples/fixture-project
$ ../../target/debug/envaudit scan . > ../expected-output.txt
$ ../../target/debug/envaudit scan . --json > ../expected-output.json
```

## Related tools

| Tool | What it does |
| --- | --- |
| [Migration Guard](https://github.com/hix-pro/migration-guard) | statically catch dangerous SQL migrations before they run |
| [API Watch](https://github.com/hix-pro/api-watch) | catch breaking changes in your OpenAPI and JSON contracts |
| [RepoRace](https://github.com/hix-pro/reporace) | see which GitHub repositories are accelerating |
| [TypeShift](https://github.com/hix-pro/typeshift) | decide the semver bump from a TypeScript declaration diff |
| [ActionLens](https://github.com/hix-pro/action-lens) | see what a GitHub Actions workflow really does, before it hits main |
| [ComposeMap](https://github.com/hix-pro/compose-map) | understand your Docker Compose stack and its production risks at a glance |
| [OpenCode Telegram](https://github.com/hix-pro/opencode-telegram) | control a local OpenCode server from Telegram |
---

_Part of the **[hix tools](https://github.com/hix-pro#readme)** suite — local-first, no backend, CI-ready._

**Deep dive:** [Catching env var drift before it breaks prod](https://hix-pro.github.io/blog/posts/01-env-audit-env-var-drift.html)

## License

MIT. See [LICENSE](LICENSE).
