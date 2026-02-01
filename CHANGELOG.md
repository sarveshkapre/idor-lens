# CHANGELOG

## Unreleased

### Added

- `idor-lens report` renders a clean HTML report from JSONL output.
- `idor-lens compare` compares baseline vs current JSONL (regression mode).
- `idor-lens init` writes a starter YAML spec.
- Spec support for `victim/attacker` cookies + preflight requests.
- Env var expansion in spec strings (`$VAR` / `${VAR}`).
- `idor-lens run` supports `--proxy` and `--insecure`.
- `idor-lens run` supports `--follow-redirects` / `--no-follow-redirects`.

### Changed

- JSONL findings now include more proof fields (URL, timing, bytes + sha256, truncation, request errors).
- `idor-lens run` supports `--out -`, `--fail-on-vuln`, and `--strict-body-match`.
- When using `--out -`, status output is written to stderr to keep stdout as pure JSONL.

## v0.1.0 - 2026-01-31

- Differential IDOR tester with YAML spec input.
- JSONL report output.
