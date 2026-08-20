# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-08-21

### Added
- Initial stable release.
- `depscope scan` — count packages grouped by source.
- `depscope risks` — human-readable risk report (JSON via `--json`).
- `depscope sbom` — minimal CycloneDX 1.5 SBOM.
- `depscope check` — CI gate, non-zero exit on High/Medium risk.
- Library API: `from_lockfile`, `detect_risks`, `summarize`, `to_sbom`, `sbom_json`.
- 8 unit tests covering risk heuristics, severity ordering and SBOM output.
- CI (GitHub Actions): build / test / clippy / rustfmt on Ubuntu + macOS.
