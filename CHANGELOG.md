# CHANGELOG

## Unreleased

### Added

- `idor-lens report` renders a clean HTML report from JSONL output.
- `idor-lens compare` compares baseline vs current JSONL (regression mode).

### Changed

- JSONL findings now include more proof fields (URL, timing, bytes + sha256, truncation, request errors).
- `idor-lens run` supports `--out -`, `--fail-on-vuln`, and `--strict-body-match`.

## v0.1.0 - 2026-01-31

- Differential IDOR tester with YAML spec input.
- JSONL report output.
