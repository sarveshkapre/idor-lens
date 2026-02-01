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

## Next (tight scope)

- Add baseline regression compare mode (fail only on new vulns).
- Improve auth realism (cookie support and/or preflight requests).
  - Add per-endpoint cookie overrides if needed.

## Non-goals (near-term)

- Auto-discovery of endpoints.
- Browser session capture.
