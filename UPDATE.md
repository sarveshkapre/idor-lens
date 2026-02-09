# Update (2026-02-09)

## Summary

- Added endpoint + preflight payload mode support via `body_mode` (`json`, `form`, `raw`).
- Added payload `content_type` controls and per-role endpoint overrides (`victim_content_type`, `attacker_content_type`).
- Added per-role endpoint payload mode overrides (`victim_body_mode`, `attacker_body_mode`).
- Extended `idor-lens validate` to fail fast on payload mode/body mismatches.
- Added SARIF export (`idor-lens sarif`) for security dashboard ingestion.

## Verification evidence

```bash
make check
```

```bash
.venv/bin/python -m idor_lens run --spec /tmp/idor_form_smoke.yml --out /tmp/idor_form_smoke.jsonl --strict-body-match
.venv/bin/python -m idor_lens summarize --in /tmp/idor_form_smoke.jsonl
```

# Update (2026-02-08)

## Summary

- Added endpoint-level cookie overrides: `endpoints[].cookies`, `victim_cookies`, and `attacker_cookies`.
- Added optional endpoint `name` labels in findings and surfaced them in report/compare/summarize outputs.
- Hardened `idor-lens validate` with run-critical schema checks (preflight structure, timeout/retry ranges, headers/cookies map typing).
- Improved malformed JSONL diagnostics with source + line/column information.

## Verification evidence

```bash
make check
```

```bash
python -m idor_lens run --spec /tmp/idor_smoke_spec.yml --out /tmp/idor_smoke_report.jsonl --strict-body-match
python -m idor_lens summarize --in /tmp/idor_smoke_report.jsonl
```

# Update (2026-02-01)

## Summary

- Improved `idor-lens run` with richer JSONL proof, stdout output, and CI/regression flags.
- Added `idor-lens report` to render a standalone HTML report.
- Added `idor-lens compare` to fail CI only on *new* vulnerabilities vs a baseline.
- Added spec support for cookies + preflight requests for more realistic auth flows.
- Added env var expansion in spec strings (`$VAR` / `${VAR}`) to avoid hardcoding secrets.
- When using `--out -`, the run summary is printed to stderr to keep stdout as pure JSONL.
- Added `--proxy` and `--insecure` for better local testing (Burp/self-signed TLS).
- Added `idor-lens init` to generate a starter `spec.yml`.
- Added `--follow-redirects`/`--no-follow-redirects` (default: do not follow redirects).
- Added `--retries`/`--retry-backoff` to stabilize scans against transient failures (timeouts, 429/502/503/504).
- Added per-role/per-endpoint timeouts in the YAML spec for slow endpoints.
- Added `idor-lens validate` to check specs and fail when env vars are missing.
- Added `idor-lens summarize` to quickly extract counts from JSONL outputs.

## How to run

```bash
make setup
make check
```

## Examples

Run a scan and stream JSONL to stdout:

```bash
python -m idor_lens run --spec spec.yml --out - --fail-on-vuln
```

Render HTML:

```bash
python -m idor_lens report --in idor-report.jsonl --out idor-report.html
```

Regression compare:

```bash
python -m idor_lens compare --baseline baseline.jsonl --current idor-report.jsonl --fail-on-new
```

## Shipping

- Work is committed directly to `main` (no PR requested).
- Push with: `git push origin main`
