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
