# PROJECT_MEMORY

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
