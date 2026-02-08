# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P0: Add auth token rotation helpers for expiring credentials during long scans.
- [ ] P1: Add non-JSON request body modes (`data`/raw payload + content-type controls).
- [ ] P1: Add configurable deny-status heuristics to reduce status-only false positives.
- [ ] P2: Add optional JUnit/SARIF export for CI/security dashboard ingestion.
- [ ] P2: Add lightweight endpoint batching/parallelism with rate-limit-aware controls.

## Implemented
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

## Notes
- This file is maintained by the autonomous clone loop.
