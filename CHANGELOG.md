# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- GitHub Actions CI workflow with test, lint, and high-severity security checks.
- Open-source project policy files: LICENSE, SECURITY.md, and CODE_OF_CONDUCT.md.

## [0.3.0] - 2026-05-10

### Added
- Full argparse CLI (`runtime-guard`) with `--snapshot`, `--check`, `--report`,
  `--generate-wslconfig`, `--posture`, `--stage`, and `--version`.
- 19 additional tests for recent fixes and CLI behavior.
- README expansion: full API reference, architecture, WSL utilities, and FAQ.

### Changed
- Windows memory reader now uses PowerShell `Get-CimInstance` first with `wmic`
  fallback for older builds.
- macOS snapshot reader now uses `sysctl hw.pagesize` and locale-safe parsing.
- Cooldown deduplication is now per `(stage, severity)` instead of global.
- `generate_wslconfig()` now merges managed keys and creates backups.

### Fixed
- KI-001: macOS locale-sensitive page-size parsing.
- KI-002: reliance on deprecated `wmic` on modern Windows.
- KI-003: forked child process stale background-thread state.
- KI-004: cooldown suppression incorrectly shared across stages.
- KI-005: unsupported-platform path returned silent zero snapshot.
- KI-006: `.wslconfig` overwrite without backup/merge.

## [0.2.0] - 2026-05-02

### Added
- Threshold presets (`tight`, `relaxed`, `ci`).
- Structured JSON events on `runtime_guard.events`.
- Cooldown/deduplication support.
- Background daemon check support.
- Initial WSL reporting and kernel tuning helpers.
