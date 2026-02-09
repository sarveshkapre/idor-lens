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
