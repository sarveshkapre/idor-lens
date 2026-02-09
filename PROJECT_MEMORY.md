# PROJECT_MEMORY

## 2026-02-09 - Streaming Response Reads

- Decision: Read response bodies via streaming iteration (still hashing/sampling up to `--max-bytes`) to avoid buffering large responses in memory.
- Why: Some IDOR targets return very large responses; buffering full bodies creates avoidable memory pressure and reduces scan reliability.
- Evidence:
  - Implementation: `src/idor_lens/runner.py`
  - Tests: `tests/test_runner.py`
  - Verification: `make check` (pass)
- Commit: `1d0620e`
- Confidence: high
- Trust label: verified-local

## 2026-02-09 - auth_file Token Rotation Helper

- Decision: Add `victim/attacker.auth_file` to read the full `Authorization` header value from a file per request; enforce mutual exclusivity with `auth`.
- Why: Real tokens expire during long scans; file-based rotation is simple, CI-friendly, and works with external refreshers without embedding refresh logic into specs.
- Evidence:
  - Runner + validation: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`
  - Template/docs: `src/idor_lens/template.py`, `README.md`, `docs/spec-cookbook.md`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`
  - Verification: `make check` (pass)
- Commit: `a7cf919`
- Confidence: high
- Trust label: verified-local
- Follow-ups:
  - Consider an opt-in `auth_command` helper for cases where file rotation is awkward.

## 2026-02-09 - replay Subcommand

- Decision: Add `idor-lens replay` to replay a single endpoint selected by `--name`, `--path`, or `--index` from an existing spec.
- Why: Iterating on headers/cookies/deny heuristics is fastest when you can replay one scenario without editing specs or running a full scan.
- Evidence:
  - CLI: `src/idor_lens/cli.py`
  - Docs: `README.md`
  - Tests: `tests/test_smoke.py`
  - Verification: `make check` (pass)
- Commit: `2690d34`
- Confidence: high
- Trust label: verified-local

## 2026-02-09 - JSON Ignore Paths For Strict Matching

- Decision: Add `json_ignore_paths` (spec-level + per-endpoint) to ignore known-dynamic JSON fields when using `--strict-body-match`, plus treat empty response bodies as a match.
- Why: Strict body matching reduces false positives, but it becomes unusable on JSON APIs that include timestamps/request IDs. Empty 2xx bodies (e.g. 204) should also be comparable in strict mode.
- Evidence:
  - Implementation: `src/idor_lens/json_paths.py`, `src/idor_lens/runner.py`
  - Validation: `src/idor_lens/validate.py`
  - Docs: `README.md`, `PLAN.md`, `CHANGELOG.md`, `src/idor_lens/template.py`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`
  - Verification: `make check` (pass, includes `tests/test_smoke.py::test_cli_run_with_json_ignore_paths_smoke`)
- Commit: `daa89e4`
- Confidence: high
- Trust label: verified-local
- Follow-ups:
  - Consider streaming body reads to avoid buffering large responses when `--max-bytes` is small.

## 2026-02-09 - Payload Mode Compatibility

- Decision: Add endpoint and preflight payload-mode support via `body_mode` (`json`, `form`, `raw`) with endpoint role overrides (`victim_body_mode`, `attacker_body_mode`) and optional payload `content_type` controls.
- Why: Runner was effectively JSON-only, which blocked common IDOR checks on form or raw-body APIs and reduced real-world hit rate.
- Evidence:
  - Runtime implementation: `src/idor_lens/runner.py`
  - Validation guardrails: `src/idor_lens/validate.py`
  - Template/docs updates: `src/idor_lens/template.py`, `README.md`, `PLAN.md`, `ROADMAP.md`, `CHANGELOG.md`, `UPDATE.md`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`
  - Verification: `make check` (pass), local CLI smoke using a temporary POST echo server + `idor_lens run`/`summarize` (pass)
- Commit: `32d6013`
- Confidence: high
- Trust label: verified-local
- Follow-ups:
  - Add auth token rotation helpers for long-running scans.
  - Add configurable deny-status heuristics for noisy targets.
  - Consider JUnit/SARIF export for CI/security platform ingestion.

## 2026-02-09 - SARIF Export

- Decision: Add SARIF 2.1.0 export (`idor-lens sarif`) from JSONL output.
- Why: SARIF is a common interchange format for security result ingestion (notably GitHub code scanning), which makes IDOR Lens runs easier to operationalize in CI.
- Evidence:
  - Implementation: `src/idor_lens/sarif.py`, `src/idor_lens/cli.py`
  - Tests: `tests/test_sarif.py`
  - Docs: `README.md`, `CHANGELOG.md`, `PLAN.md`, `ROADMAP.md`, `UPDATE.md`, `CLONE_FEATURES.md`
  - Verification: `make check` (pass); CLI smoke: `.venv/bin/python -m idor_lens sarif --in <tmp>.jsonl --out <tmp>.sarif` (pass)
- Commit: `9205646`
- Confidence: high
- Trust label: verified-local

## 2026-02-09 - Deny-Response Heuristics

- Decision: Add configurable deny heuristics via `deny_contains` / `deny_regex` (spec-level + per-endpoint), and include `victim_deny_match` / `attacker_deny_match` in findings output.
- Why: Some targets return 2xx denial pages, making status-only differential checks noisy; heuristics let users reduce false positives without forcing strict body matching everywhere.
- Evidence:
  - Runner: `src/idor_lens/runner.py`
  - Validation: `src/idor_lens/validate.py`
  - Spec template: `src/idor_lens/template.py`
  - Report: `src/idor_lens/report.py`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`
  - Verification: `make check` (pass)
- Commit: `71eeb91`
- Confidence: medium-high
- Trust label: verified-local
- Follow-ups:
  - Consider adding a structured "deny signal" mode that supports matching on headers/status/body together (to reduce overfitting to body text).

## 2026-02-09 - GitHub Actions CI Examples

- Decision: Add copy/paste GitHub Actions templates for fail-on-vuln, regression compare, and SARIF upload.
- Why: CI integration is the fastest path to real adoption; concrete templates reduce friction and prevent DIY mistakes around environment/secrets, baseline compare, and SARIF upload permissions.
- Evidence:
  - Docs: `docs/ci-github-actions.md`, `examples/github-actions/idor-lens-regression.yml`, `README.md`
  - Verification: `make check` (pass); GitHub Actions `ci` workflow success for commit `a86a1dc` (via `gh run watch 21819486082 --exit-status`)
- Commit: `a86a1dc`
- Confidence: high
- Trust label: verified-local
