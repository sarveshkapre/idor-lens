# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1: Add explicit status heuristics (`allow_statuses` / `deny_statuses`) for apps that encode access control in non-2xx patterns.
  - Score: impact=medium-high, effort=medium, fit=high, differentiation=medium, risk=low, confidence=medium.
- [ ] P1: Add `--debug-requests` mode with redacted request/response metadata (method/url/status/body sample) to reduce spec iteration time.
  - Score: impact=medium, effort=medium, fit=high, differentiation=low, risk=medium, confidence=medium.
- [ ] P2: Add lightweight endpoint batching/parallelism (`--max-in-flight`) with conservative defaults.
  - Score: impact=medium, effort=high, fit=medium, differentiation=medium, risk=high, confidence=low.
- [ ] P2: Add adaptive rate-limit behavior (`Retry-After` respect + jittered backoff caps) for noisy APIs/WAFs.
  - Score: impact=medium, effort=medium, fit=high, differentiation=low, risk=medium, confidence=medium.
- [ ] P2: Add optional `auth_command` token refresh helper with explicit opt-in and execution timeout guardrails.
  - Score: impact=medium, effort=medium, fit=high, differentiation=medium, risk=medium, confidence=medium-low.
- [ ] P2: Add endpoint tags and `--only-tag` selector for large specs (complements `--only-name`/`--only-path`).
  - Score: impact=medium, effort=low-medium, fit=high, differentiation=low, risk=low, confidence=high.
- [ ] P2: Add per-endpoint request fingerprinting controls (header/body/content-length signals) to reduce false positives on template-heavy denial pages.
  - Score: impact=medium, effort=medium-high, fit=high, differentiation=medium, risk=medium, confidence=medium-low.
- [ ] P2: Add a `baseline` helper command to capture/version canonical JSONL snapshots for easier compare workflows.
  - Score: impact=low-medium, effort=low, fit=medium, differentiation=low, risk=low, confidence=high.
- [ ] P3: Add multi-role authorization matrix support (>2 roles) while keeping victim/attacker shorthand backward compatible.
  - Score: impact=medium, effort=high, fit=medium, differentiation=high, risk=high, confidence=low.
- [ ] P3: Add richer HTML report faceting (filter by reason/confidence/role outcome) for faster analyst triage.
  - Score: impact=low-medium, effort=medium, fit=medium, differentiation=low, risk=low, confidence=medium.
- [ ] P3: Add optional response artifact capture for failing scenarios (small sample snapshots) with secret-safe redaction.
  - Score: impact=low-medium, effort=medium, fit=medium, differentiation=low, risk=medium, confidence=medium-low.

## Implemented
- [x] 2026-02-11: Added endpoint `matrix` expansion with `{{var}}` placeholders (path/query/body/name/header/cookie), plus `matrix_values` in findings and compare/summarize keying for stable per-variant regression tracking.
  Evidence: `src/idor_lens/matrix.py`, `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/findings.py`, `src/idor_lens/report.py`, `src/idor_lens/schema.py`, `docs/idor-lens.schema.json`, `src/idor_lens/template.py`, `README.md`, `docs/spec-cookbook.md`, `tests/test_runner.py`, `tests/test_validate.py`, `tests/test_compare.py`, `tests/test_summarize.py`, `tests/test_smoke.py`; gate: `make check`; local smoke: `.venv/bin/python -m idor_lens run ...` + `.venv/bin/python -m idor_lens summarize ...`; commit: `17bb854`.
- [x] 2026-02-10: Added `allow_contains` / `allow_regex` heuristics (spec-level + per-endpoint) to reduce status-only false positives when attacker receives a 2xx denial page.
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/report.py`, `src/idor_lens/template.py`, `docs/spec-cookbook.md`, `README.md`, `tests/test_runner.py`, `tests/test_validate.py`; gate: `make check`; commit: `8ae1d6e`.
- [x] 2026-02-10: Published a JSON Schema for the YAML spec and added `idor-lens schema --out -` for editor IntelliSense and downstream validation.
  Evidence: `src/idor_lens/schema.py`, `src/idor_lens/cli.py`, `docs/idor-lens.schema.json`, `tests/test_schema.py`, `README.md`, `CHANGELOG.md`; gate: `make check`; commit: `edc2363`.
- [x] 2026-02-09: Added `idor-lens run --only-name/--only-path` filters to run a subset of endpoints for faster iteration.
  Evidence: `src/idor_lens/cli.py`, `src/idor_lens/runner.py`, `tests/test_runner.py`, `README.md`, `CHANGELOG.md`; gate: `make check`.
- [x] 2026-02-09: Added `--max-response-bytes` to cap response reads (prevents hanging on huge/streaming endpoints); surfaced in JSONL and HTML report details.
  Evidence: `src/idor_lens/cli.py`, `src/idor_lens/runner.py`, `src/idor_lens/report.py`, `tests/test_runner.py`, `README.md`, `CHANGELOG.md`; gate: `make check`.
- [x] 2026-02-09: Streamed response reads in runner (hash/sample up to `--max-bytes` without buffering full bodies).
  Evidence: `src/idor_lens/runner.py`, `tests/test_runner.py`; gate: `make check`.
- [x] 2026-02-09: Added `auth_file` support for rotating `Authorization` header tokens during long scans (read per request).
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/template.py`, `docs/spec-cookbook.md`, `README.md`, `tests/test_runner.py`, `tests/test_validate.py`; gate: `make check`.
- [x] 2026-02-09: Added `idor-lens replay` to replay a single endpoint from a spec for debugging.
  Evidence: `src/idor_lens/cli.py`, `README.md`, `tests/test_smoke.py`; gate: `make check`.
- [x] 2026-02-09: Improved response diffing: allow ignoring dynamic fields (e.g. timestamps) for strict matching via `json_ignore_paths`.
  Evidence: `src/idor_lens/json_paths.py`, `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/template.py`, `tests/test_runner.py`, `tests/test_validate.py`, `tests/test_smoke.py`, `README.md`, `PLAN.md`, `CHANGELOG.md`; gate: `make check`.
- [x] 2026-02-09: Added a small "spec cookbook" doc with patterns: CSRF preflight, cookie auth, proxying via Burp, deny heuristics, and strict-body tuning.
  Evidence: `docs/spec-cookbook.md`, `README.md`; gate: `make check`.
- [x] 2026-02-09: Added GitHub Actions CI workflow examples (fail-on-vuln, regression compare, SARIF upload).
  Evidence: `docs/ci-github-actions.md`, `examples/github-actions/idor-lens-regression.yml`, `README.md`; gate: `make check`.
- [x] 2026-02-09: Added configurable deny-response heuristics via `deny_contains` / `deny_regex` (spec-level + per-endpoint).
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/template.py`, `src/idor_lens/report.py`, `tests/test_runner.py`, `tests/test_validate.py`, `README.md`, `CHANGELOG.md`; gate: `make check`.
- [x] 2026-02-09: Added SARIF export (`idor-lens sarif`) for GitHub code scanning / security dashboard ingestion.
  Evidence: `src/idor_lens/sarif.py`, `src/idor_lens/cli.py`, `tests/test_sarif.py`, `README.md`, `CHANGELOG.md`; gate: `make check`.
- [x] 2026-02-09: Added JUnit XML export (`idor-lens junit`) for CI ingestion.
  Evidence: `src/idor_lens/junit.py`, `src/idor_lens/cli.py`, `tests/test_junit.py`; gate: `make check`.
- [x] 2026-02-09: Added endpoint + preflight payload modes (`body_mode`: `json`/`form`/`raw`) with per-endpoint role overrides (`victim_body_mode`, `attacker_body_mode`).
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/template.py`, `tests/test_runner.py::test_endpoint_form_body_mode_sends_data_with_content_type`, `tests/test_validate.py::test_validate_accepts_payload_modes_and_content_type`.
- [x] 2026-02-09: Added payload `content_type` controls and defaults (`form` => `application/x-www-form-urlencoded`, `raw` => `text/plain; charset=utf-8`).
  Evidence: `src/idor_lens/runner.py`, `README.md`, `tests/test_runner.py::test_endpoint_raw_body_mode_defaults_to_text_plain`.
- [x] 2026-02-09: Enforced payload schema validation for mode/body mismatches and invalid body modes.
  Evidence: `src/idor_lens/validate.py`, `tests/test_validate.py::test_validate_rejects_unknown_body_mode`, `tests/test_validate.py::test_validate_rejects_non_mapping_form_body`, `tests/test_validate.py::test_validate_rejects_non_string_raw_body`.
- [x] 2026-02-09: Completed local verification for payload modes with canonical gate plus real CLI smoke path against a local POST echo server.
  Evidence: `make check`; `.venv/bin/python -m idor_lens run --spec <tmp> --out <tmp> --strict-body-match`; `.venv/bin/python -m idor_lens summarize --in <tmp>`.
- [x] 2026-02-08: Added endpoint cookie overrides (`endpoints[].cookies`, `victim_cookies`, `attacker_cookies`) with endpoint-level precedence.
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/template.py`, `tests/test_runner.py::test_endpoint_name_and_cookie_overrides_are_applied`.
- [x] 2026-02-08: Added endpoint `name` support in findings and keying logic for compare/summarize; surfaced in HTML report.
  Evidence: `src/idor_lens/runner.py`, `src/idor_lens/compare.py`, `src/idor_lens/summarize.py`, `src/idor_lens/report.py`, `tests/test_compare.py::test_compare_prefers_name_for_keys`, `tests/test_summarize.py::test_summarize_prefers_name_for_keys`.
- [x] 2026-02-08: Expanded `idor-lens validate` with run-critical schema checks (timeouts/retries/preflight/header-cookie typing).
  Evidence: `src/idor_lens/validate.py`, `tests/test_validate.py`.
- [x] 2026-02-08: Improved JSONL parse diagnostics with source + line/column context.
  Evidence: `src/idor_lens/jsonl.py`, `tests/test_jsonl.py`.
- [x] 2026-02-08: Updated docs/changelog/project memory and validated locally.
  Evidence: `README.md`, `CHANGELOG.md`, `PLAN.md`, `ROADMAP.md`, `UPDATE.md`; commands: `make check`, local CLI smoke run against `python -m http.server`.

## Insights
- Gap map (2026-02-11): `missing`=intruder-style parameterized coverage (closed this cycle via endpoint matrix support), `weak`=status semantics for non-2xx denial patterns, `parity`=CI exports (JUnit/SARIF + compare), `differentiator opportunity`=rate-limit-aware parallelism plus rich deny/allow signal controls.
- Schema drift between `run` and `validate` was a practical reliability risk; mirroring runtime-critical checks in `validate` prevents avoidable scan-time failures.
- Naming scan scenarios in specs (`endpoints[].name`) makes regression output materially clearer when multiple checks hit the same path.
- JSONL tooling benefits from explicit parse-location errors because report/compare/summarize are often run in CI where raw tracebacks are noisy.
- Payload mode defaults must stay explicit and deterministic to keep scan reproducibility high across differing API stacks.
- Allow heuristics are a practical middle ground between status-only signals and full strict-body matching: they reduce noisy 2xx denial page false positives without requiring full response equivalence.
- JSON Schema output is disproportionately valuable for adoption: it shortens the "write a spec" loop via editor IntelliSense and reduces typo-driven failures.
- Market scan (untrusted web signal, refreshed 2026-02-11): established workflows emphasize (1) role/session realism, (2) response diffing beyond status codes, and (3) CI/security-dashboard friendly exports.
  - Burp Suite extension patterns for authorization testing emphasize matrix-style request replay across users and mismatch-focused reporting.
    - https://github.com/PortSwigger/auth-matrix (AuthMatrix docs)
    - https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f (Autorize listing)
  - Baseline problem framing remains IDOR/BOLA-focused in PortSwigger and OWASP guidance.
    - https://portswigger.net/web-security/access-control/idor
    - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - Additional authorization-testing extension patterns (untrusted web signal): enforcement detectors often support fingerprints in body/headers and/or content-length-based matching, plus per-user vs global rules.
    - https://github.com/emanuelfc/Authorize (Authorize extension)
  - SARIF 2.1.0 is a common interchange format for ingesting scan results (e.g. GitHub code scanning).
    - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Notes
- This file is maintained by the autonomous clone loop.
