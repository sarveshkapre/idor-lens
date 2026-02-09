# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1: Add `idor-lens run --only-name/--only-path` filters for faster iteration in CI and local debugging (replay exists, but filtering helps keep JSONL naming and CI wiring stable).
  - Score: impact=high, effort=low, fit=high, differentiation=low, risk=low, confidence=high.
- [ ] P1: Add a `--max-response-bytes` hard cap (stop reading after N bytes) for hostile endpoints that stream indefinitely or return huge bodies.
  - Score: impact=high, effort=medium, fit=high, differentiation=low, risk=medium, confidence=medium.
- [ ] P2: Add parametrized endpoint matrices (intruder-style ID substitution over path/query/body) to increase coverage.
  - Score: impact=high, effort=high, fit=high, differentiation=high, risk=medium, confidence=medium-low.
- [ ] P2: Add richer allow/deny heuristics beyond status codes (e.g. `allow_contains`/`allow_regex` + optional header/content-length matching), to reduce false positives on apps that return 2xx deny pages and false negatives on apps that use 404-on-deny patterns.
  - Score: impact=high, effort=medium, fit=high, differentiation=medium, risk=medium, confidence=medium.
- [ ] P2: Add a debug mode that logs outgoing requests (method/url/headers and small body sample) with redaction rules, to speed up spec iteration without opening Burp.
  - Score: impact=medium, effort=medium, fit=high, differentiation=low, risk=medium, confidence=medium.
- [ ] P2: Add an optional token refresh command helper (`auth_command`) with explicit opt-in guardrails for long scans where `auth_file` is inconvenient.
  - Score: impact=medium, effort=medium, fit=high, differentiation=medium, risk=medium, confidence=medium-low.
- [ ] P3: Add lightweight endpoint batching/parallelism with rate-limit-aware controls (max in-flight, 429 backoff).
  - Score: impact=medium, effort=high, fit=medium, differentiation=medium, risk=high, confidence=low.
- [ ] P3: Add multi-role support (more than victim/attacker) to allow authorization matrices similar to common Burp workflows.
  - Score: impact=medium, effort=high, fit=medium, differentiation=high, risk=high, confidence=low.
- [ ] P3: Publish a JSON Schema for the YAML spec (and/or `idor-lens schema --out -`) for editor IntelliSense and downstream validation.
  - Score: impact=medium, effort=medium, fit=high, differentiation=low, risk=low, confidence=medium.
- [ ] P3: Add a `--strict-status`/`--deny-statuses` control to treat non-2xx patterns explicitly (useful when targets use 404/200 in unusual ways).
  - Score: impact=low-medium, effort=low-medium, fit=medium, differentiation=low, risk=low, confidence=medium.

## Implemented
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
- Schema drift between `run` and `validate` was a practical reliability risk; mirroring runtime-critical checks in `validate` prevents avoidable scan-time failures.
- Naming scan scenarios in specs (`endpoints[].name`) makes regression output materially clearer when multiple checks hit the same path.
- JSONL tooling benefits from explicit parse-location errors because report/compare/summarize are often run in CI where raw tracebacks are noisy.
- Payload mode defaults must stay explicit and deterministic to keep scan reproducibility high across differing API stacks.
- Market scan (untrusted web signal): established workflows emphasize (1) role/session realism, (2) response diffing beyond status codes, and (3) CI/security-dashboard friendly exports.
  - Burp Suite extensions commonly used for authorization testing: AuthMatrix and Autorize.
    - https://portswigger.net/bappstore/cbff8e57c1cf4c66af0d9c1c0a6d6e1b (AuthMatrix)
    - https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f (Autorize)
  - AuthMatrix/Autorize UX patterns worth matching (non-proprietary patterns): fast "replay" of a single request across roles, explicit allow/deny signals beyond status codes, and summarizing mismatches by endpoint key.
    - https://github.com/PortSwigger/auth-matrix (AuthMatrix docs)
    - https://github.com/PortSwigger/autorize (Autorize docs)
  - Additional authorization-testing extension patterns (untrusted web signal): enforcement detectors often support fingerprints in body/headers and/or content-length-based matching, plus per-user vs global rules.
    - https://github.com/emanuelfc/Authorize (Authorize extension)
  - PortSwigger Web Security Academy guidance: Insecure direct object references (IDOR).
    - https://portswigger.net/web-security/access-control/idor
  - OWASP API Security Top 10: API1:2023 Broken Object Level Authorization (BOLA), the API-world equivalent of IDOR.
    - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - SARIF 2.1.0 is a common interchange format for ingesting scan results (e.g. GitHub code scanning).
    - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Notes
- This file is maintained by the autonomous clone loop.
