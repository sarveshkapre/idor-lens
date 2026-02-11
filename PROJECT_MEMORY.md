# PROJECT_MEMORY

## 2026-02-11 - Endpoint Matrix Expansion For Coverage

- Decision: Add endpoint `matrix` expansion with `{{var}}` placeholders to generate cartesian endpoint variants across path/query/body/name/header/cookie fields.
- Why: Spec-authoring effort was a top coverage bottleneck; intruder-style parameterization materially increases object-level authorization coverage without duplicating endpoint definitions.
- Evidence:
  - Implementation: `src/idor_lens/matrix.py`, `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/schema.py`
  - Keying/triage: `src/idor_lens/findings.py`, `src/idor_lens/report.py`
  - Docs: `README.md`, `docs/spec-cookbook.md`, `src/idor_lens/template.py`, `PLAN.md`, `ROADMAP.md`, `CHANGELOG.md`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`, `tests/test_compare.py`, `tests/test_summarize.py`, `tests/test_smoke.py`
  - Verification: `make check` (pass); local CLI smoke matrix run + summarize (pass)
- Commit: `17bb854`
- Confidence: high
- Trust label: verified-local

## 2026-02-11 - Decision: Matrix Values In Regression Keys

- Decision: Include `matrix_values` in findings and append them to compare/summarize keys when present.
- Why: Without variant identity in keys, matrix-expanded runs with shared path/name can collapse in regression output and hide variant-specific results.
- Evidence:
  - Implementation: `src/idor_lens/runner.py`, `src/idor_lens/findings.py`
  - Tests: `tests/test_compare.py::test_compare_keys_include_matrix_values`, `tests/test_summarize.py::test_summarize_keys_include_matrix_values`
  - Verification: `make check` (pass); local summarize output includes matrix-qualified keys (pass)
- Commit: `17bb854`
- Confidence: high
- Trust label: verified-local

## 2026-02-11 - Market Scan Snapshot (Bounded)

- Decision: Prioritize matrix-style coverage in this cycle, then keep status-heuristic and parallelism work as next backlog.
- Why: External signals consistently emphasize authorization matrix replay and BOLA/IDOR coverage breadth as baseline expectations.
- Evidence (untrusted web signal):
  - AuthMatrix repository (matrix-style authorization testing workflow): https://github.com/PortSwigger/auth-matrix
  - Autorize listing (authorization replay extension signal): https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f
  - PortSwigger IDOR guidance: https://portswigger.net/web-security/access-control/idor
  - OWASP API1:2023 BOLA guidance: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Commit: `17bb854`
- Confidence: medium
- Trust label: untrusted-web

## 2026-02-11 - Mistake: Initial Smoke Script Race (Fixed)

- Root cause: A shell-based smoke script attempted to read a dynamically written port file before it existed, producing an invalid spec URL.
- Fix: Replaced the ad-hoc shell orchestration with a single Python smoke harness that starts the server thread, runs CLI commands, and shuts down deterministically.
- Prevention rule: For local integration checks requiring ephemeral ports/processes, prefer one-process Python harnesses over multi-step shell background orchestration.
- Evidence: one failed shell smoke attempt, followed by successful `.venv/bin/python - <<'PY' ...` CLI smoke harness.
- Commit: `17bb854`
- Confidence: high
- Trust label: verified-local

## 2026-02-11 - Verification Evidence (Cycle 1)

- `.venv/bin/python -m idor_lens schema --out docs/idor-lens.schema.json` (pass)
- `.venv/bin/pytest -q tests/test_validate.py tests/test_runner.py tests/test_compare.py tests/test_summarize.py tests/test_smoke.py` (pass)
- `make check` (pass)
- `.venv/bin/python - <<'PY' ... matrix smoke harness running \`idor_lens run\` + \`idor_lens summarize\` ...` (pass)
- `gh issue list --limit 100 --state open --json number,title,author,labels,updatedAt` (pass; no open issues)
- `gh run list --limit 20 --json databaseId,headBranch,headSha,name,status,conclusion,workflowName,createdAt,updatedAt` (pass; recent runs successful)
- `gh run watch 21896183044 --exit-status` (pass; GitHub Actions `ci` successful for commit `17bb854`)

## 2026-02-10 - Allow Heuristics For Noisy 2xx Denial Pages

- Decision: Add `allow_contains` / `allow_regex` heuristics (spec-level + per-endpoint) and treat a role as "allowed" only when `2xx AND allow_match AND NOT deny_match` when allow heuristics are configured.
- Why: Status-only signals are a major false-positive vector on targets that return a 2xx denial page; allow heuristics provide a low-friction way to require a positive "allowed" fingerprint without forcing full strict-body matching.
- Evidence:
  - Implementation: `src/idor_lens/runner.py`, `src/idor_lens/validate.py`, `src/idor_lens/report.py`, `src/idor_lens/template.py`
  - Docs: `README.md`, `docs/spec-cookbook.md`
  - Tests: `tests/test_runner.py`, `tests/test_validate.py`
  - Verification: `make check` (pass)
- Commit: `8ae1d6e`
- Confidence: high
- Trust label: verified-local

## 2026-02-10 - Spec JSON Schema + schema Subcommand

- Decision: Publish a JSON Schema for the YAML spec and add `idor-lens schema --out -` to emit it (kept in sync via a test against `docs/idor-lens.schema.json`).
- Why: Spec authoring is the primary UX; editor IntelliSense and lightweight schema validation reduce typo-driven failures and shorten iteration time.
- Evidence:
  - Implementation: `src/idor_lens/schema.py`, `src/idor_lens/cli.py`
  - Published schema: `docs/idor-lens.schema.json`
  - Tests: `tests/test_schema.py`
  - Verification: `make check` (pass); `.venv/bin/python -m idor_lens schema --out - | head` (pass)
- Commit: `edc2363`
- Confidence: medium-high
- Trust label: verified-local

## 2026-02-10 - Verification Evidence (Cycle 1)

- `make check` (pass)
- `.venv/bin/python -m idor_lens --help` (pass)
- `.venv/bin/python -m idor_lens schema --out - | head` (pass)
- `.venv/bin/python -m idor_lens init --out - --base-url https://example.test | head` (pass)
- `gh run list --limit 15` (pass; recent runs all successful)

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

## 2026-02-09 - run Subset Filters

- Decision: Add `idor-lens run --only-name/--only-path` filters to run a subset of endpoints from a spec.
- Why: Replay is good for single-endpoint debug, but CI and local iteration often need a stable subset run while keeping the full spec intact.
- Evidence:
  - Implementation: `src/idor_lens/cli.py`, `src/idor_lens/runner.py`
- Tests: `tests/test_runner.py`
- Verification: `make check` (pass)
- Commit: `494b77a`
- Confidence: high
- Trust label: verified-local

## 2026-02-09 - max-response-bytes Hard Cap

- Decision: Add `--max-response-bytes` to stop reading responses after N bytes, and record cap hits in output (`victim_response_capped` / `attacker_response_capped`).
- Why: Prevent scans from hanging or consuming excessive bandwidth/memory on huge or streaming endpoints, while keeping status/heuristic checks usable.
- Evidence:
  - Implementation: `src/idor_lens/cli.py`, `src/idor_lens/runner.py`, `src/idor_lens/report.py`
  - Tests: `tests/test_runner.py`
  - Verification: `make check` (pass)
- Commit: `efbe7c4`
- Confidence: medium-high
- Trust label: verified-local

## 2026-02-09 - Verification Evidence (Cycle 5)

- `make check` (pass)
- `gh run list --limit 10` (pass; recent runs all successful)

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
- Commit: `2690d34`, `b756b56`
- Confidence: high
- Trust label: verified-local

## 2026-02-09 - Mistake: replay Leaked Expanded Env Vars To Disk (Fixed)

- Root cause: `idor-lens replay` initially loaded specs via `load_spec()`, which expands env vars. Narrowing then wrote a temporary YAML spec containing expanded secrets.
- Fix: Load the raw YAML for replay (no env expansion) and let `run` perform env expansion at execution time.
- Prevention rule: Avoid persisting expanded secret values when transforming specs; prefer operating on raw YAML and applying env expansion only at the point of request execution.
- Evidence: `src/idor_lens/cli.py`; verification: `make check` (pass)
- Commit: `b756b56`
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
