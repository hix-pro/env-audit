# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-10-31

### Added
- Python support (`.py`, `.pyw`): `os.environ["NAME"]`, `os.environ.get("NAME")`, `os.environ.setdefault(...)`, `os.environ.pop(...)`, and `os.getenv("NAME")`, including `import os as ...`, `from os import environ[, getenv]`, and aliased imports.
- JavaScript, TypeScript, TSX, and Python files are now parsed with tree-sitter instead of regular expressions. This removes false `unused` findings from matches inside comments and strings, and adds support for destructuring (`const { NAME } = process.env`), optional chaining, TypeScript `as`/`satisfies` wrappers, non-null assertions, bracket access with constant strings, template substitutions, and Deno/Bun access forms.

### Changed
- Rust, Go, and shell files keep the targeted regex scanner, where the access forms are simple and a parser would add weight without improving accuracy.
- Building from source now requires a C compiler for the tree-sitter grammars. Prebuilt release binaries are unaffected.

### Fixed
- Usages inside JavaScript/TypeScript and Python comments, string literals, and dynamic keys such as `process.env[name]` or `os.environ[key]` are no longer counted as usage, so example variables read only in those places are reported as `unused` instead of being silently treated as documented.

## [0.4.0] - 2026-10-29

### Added
- `envaudit scan --fix` appends variables reported as `missing` or `undocumented` to the primary example env file with empty values. It creates `.env.example` when no example exists, seeds a new file with runtime-declared names, never edits real env files, never writes values, and re-scans after the edit so the report and exit code describe the post-fix state.
- `envaudit scan --sarif` emits a SARIF 2.1.0 report for GitHub code scanning and other SARIF consumers. Results carry stable rule IDs, severity levels, and file/line locations relative to the repository root.
- The composite Action writes and uploads SARIF by default (`sarif: true`), with a `category` input for separating runs. The caller needs `security-events: write`; the upload never changes the scan's exit code.

## [0.3.1] - 2026-10-28

### Fixed
- Compose block sequences indented at exactly the parent key's indent (`environment:` / `env_file:` followed by `- item` at the same indent) are now parsed. They were previously treated as empty blocks, which produced false "missing" findings and silently skipped referenced env files. Workflow `env:` still ignores sequences, as before.
- `envaudit --help | head -1` no longer exits 1 with "failed to print help: Broken pipe". A closed pipe or interrupted stream while printing help, version, or usage is now treated as normal termination (exit 0).
- The text report now pads the finding-kind column on the plain name before applying color. Previously the `{:<12}` padding counted ANSI escape bytes, so colored output never aligned. Plain output is unchanged.
- A `.gitignore` that exists but cannot be read now emits a one-line stderr warning instead of being silently skipped, which could silently flip secret severities.
- The 1 MiB file-size cap is now enforced on the bytes actually read, not just on the earlier stat, so files that grow between stat and read are skipped instead of being slurped.

## [0.3.0] - 2026-10-27

### Added
- Prebuilt release binaries: version tags now trigger builds for Linux x86_64 (gnu), macOS (Apple Silicon), and Windows x86_64, attaching `envaudit-{target}.tar.gz` tarballs with SHA-256 checksums to the release.
- The composite Action prefers the prebuilt binary matching its version tag and falls back to building from source when it is not available.

## [0.2.0] - 2026-10-27

### Added
- Composite GitHub Action (`action.yml`) so workflows can run EnvAudit without installing Rust themselves; the repository dogfoods it in a dedicated Dogfood workflow.
- Initial public release.
