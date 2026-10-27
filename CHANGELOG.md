# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
