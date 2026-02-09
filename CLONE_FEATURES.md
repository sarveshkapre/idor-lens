# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P0: Add auth token rotation helpers for expiring credentials during long scans.
- [ ] P1: Add configurable deny-status heuristics to reduce status-only false positives on noisy targets.
- [ ] P2: Add optional JUnit/SARIF export for CI/security dashboard ingestion.
- [ ] P2: Add lightweight endpoint batching/parallelism with rate-limit-aware controls.

## Implemented
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

## Notes
- This file is maintained by the autonomous clone loop.
