# PLAN.md

## Product pitch

IDOR Lens is a tiny CLI that detects IDORs via differential requests (victim vs attacker credentials) and writes
minimal, CI-friendly proof as JSONL.

## Features (current)

- YAML-driven spec: `base_url`, victim/attacker auth + headers, endpoint list.
- Per-endpoint method + optional victim/attacker request body.
- Deterministic JSONL findings output for triage + regression.

## Top risks / unknowns

- False positives/negatives: status-only signals are often insufficient; body matching can be brittle with dynamic
  fields.
- Auth realism: many apps require cookies/CSRF/session bootstrap rather than a single header.
- Rate limiting / WAF / caching may skew differential results.
- Endpoint coverage depends entirely on the YAML spec (no discovery).

## Commands

See `PROJECT.md` for the canonical commands.

```bash
make setup
make check
python -m idor_lens --help
```

## Shipped (2026-02-01)

- Richer JSONL proof output (URL, timing split, bytes + sha256, truncation, request errors).
- `--out -` support (stream JSONL to stdout).
- CI/regression knobs: `--fail-on-vuln` + `--strict-body-match`.
- `idor-lens report` HTML renderer for clean triage.
- `idor-lens compare` baseline vs current regression mode (new vulns only).
- Cookie + preflight support for more realistic auth flows.
- Env var expansion in spec strings (avoid hardcoding secrets).
- `idor-lens init` to generate a starter `spec.yml`.
- Retry/backoff controls for transient errors.
- Per-role/per-endpoint timeout overrides.
- `idor-lens validate` (fail fast on missing env vars).
- `idor-lens summarize` (CI-friendly counts from JSONL).

## Shipped (2026-02-08)

- Endpoint-level cookie overrides via `endpoints[].cookies`, `victim_cookies`, and `attacker_cookies`.
- Optional endpoint `name` labels in JSONL findings, report, compare, and summarize outputs.
- `idor-lens validate` now enforces run-critical schema checks (types/ranges for retry/timeout fields, header/cookie maps, and preflight shape).
- JSONL parsing errors now include source + line/column diagnostics.

## Shipped (2026-02-09)

- Added endpoint/preflight request payload modes via `body_mode` (`json`, `form`, `raw`).
- Added endpoint payload `content_type` controls with per-role overrides (`victim_content_type`, `attacker_content_type`).
- Added per-role endpoint body-mode overrides (`victim_body_mode`, `attacker_body_mode`).
- Extended `idor-lens validate` to catch payload mode/body mismatch errors before scans run.
- Added SARIF export (`idor-lens sarif`) for GitHub code scanning / security dashboard ingestion.

## Next (tight scope)

- Add auth token rotation helpers for expiring credentials during long scans.
- Add configurable deny-status heuristics to reduce status-only false positives in edge cases.
- Add optional GitHub Actions workflow examples for CI/regression mode.

## Non-goals (near-term)

- Auto-discovery of endpoints.
- Browser session capture.
