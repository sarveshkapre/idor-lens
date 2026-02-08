# CHANGELOG

## Unreleased

### Added

- `idor-lens report` renders a clean HTML report from JSONL output.
- `idor-lens compare` compares baseline vs current JSONL (regression mode).
- `idor-lens init` writes a starter YAML spec.
- `idor-lens validate` validates a spec and can fail on missing env vars.
- `idor-lens summarize` summarizes JSONL output for CI/terminal use.
- Endpoint-level cookie overrides via `endpoints[].cookies`, `victim_cookies`, and `attacker_cookies`.
- Optional endpoint `name` field in findings; compare/summarize now key by `name` when provided.
- `idor-lens validate` now checks run-critical schema fields (timeouts, retries, headers/cookies maps, preflight shape).
- JSONL readers now report source + line/column for malformed rows.
- Spec support for `victim/attacker` cookies + preflight requests.
- Env var expansion in spec strings (`$VAR` / `${VAR}`).
- `idor-lens run` supports `--proxy` and `--insecure`.
- `idor-lens run` supports `--follow-redirects` / `--no-follow-redirects`.
- `idor-lens run` supports `--retries` / `--retry-backoff` for transient errors.
- Spec supports `victim/attacker.timeout` and per-endpoint timeouts.

### Changed

- JSONL findings now include more proof fields (URL, timing, bytes + sha256, truncation, request errors).
- `idor-lens run` supports `--out -`, `--fail-on-vuln`, and `--strict-body-match`.
- When using `--out -`, status output is written to stderr to keep stdout as pure JSONL.

## v0.1.0 - 2026-01-31

- Differential IDOR tester with YAML spec input.
- JSONL report output.
