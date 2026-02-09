# IDOR Lens

IDOR detector via role/token differential testing with minimal proof output.

## Scope (v0.1.0)

- YAML-driven test spec.
- Victim vs attacker token comparison.
- JSONL report output.

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m idor_lens run --spec spec.yml --out idor-report.jsonl
```

## Create a spec

Generate a starter `spec.yml`:

```bash
python -m idor_lens init --out spec.yml --base-url https://example.test
```

## Validate a spec

Validate structure and (optionally) fail if env vars are missing:

```bash
python -m idor_lens validate --spec spec.yml --require-env
```

Validation checks run-critical schema fields too (timeouts/retries, preflight shape, and header/cookie map types) so bad specs fail fast before requests are sent.

### Auth realism (cookies + preflight)

Many apps need cookies/CSRF/bootstrap requests before protected endpoints behave realistically.

Add optional `cookies` and `preflight` under `victim`/`attacker` in your spec:

```yaml
base_url: https://example.test
victim:
  auth: Bearer victim
  cookies:
    session: victim_session_cookie
  preflight:
    - path: /bootstrap
      method: GET
attacker:
  auth: Bearer attacker
  cookies:
    session: attacker_session_cookie
  preflight:
    - path: /bootstrap
      method: GET
endpoints:
  - name: item-read
    path: /items/123
    method: GET
    cookies:
      locale: en-US
    victim_cookies:
      session: victim_session_override
    attacker_cookies:
      session: attacker_session_override
```

Tips:

- Prefer env vars for secrets (strings support `$VAR` / `${VAR}` expansion):
  - `auth: Bearer ${VICTIM_TOKEN}`
- For expiring credentials during long scans, rotate tokens via `auth_file` (file contents should be the full `Authorization` header value):
  - `auth_file: /path/to/victim_auth.txt`
- Use `--proxy http://127.0.0.1:8080` to route both roles through Burp/mitmproxy.
- Use `--insecure` for self-signed TLS (e.g. local dev).
- By default redirects are not followed; use `--follow-redirects` if needed.
- For flaky targets, use `--retries 2 --retry-backoff 0.25` (retries 429/502/503/504 + timeouts).
- Use `victim.timeout` / `attacker.timeout` / per-endpoint `timeout` overrides for slow endpoints.
- Use endpoint `name` to label scenarios; compare/summarize keys prefer this when present.
- Use endpoint/preflight `body_mode` when targets expect non-JSON payloads (`json`/`form`/`raw`).
- Use `--out -` to stream JSONL to stdout.
- Use `--fail-on-vuln` for CI/regression.
- Use `--strict-body-match` to reduce false positives when attacker gets a different 2xx body.
- For strict matching on JSON APIs with dynamic fields (timestamps, request IDs), add `json_ignore_paths` to the spec (best-effort):

```yaml
json_ignore_paths:
  - /updatedAt
  - /requestId
  - /items/*/updatedAt
```
- For apps that return a 2xx "access denied" page, use `deny_contains` / `deny_regex` in your spec to override status-only signals.
- For more spec patterns (cookies/CSRF, proxying, strict matching tuning), see `docs/spec-cookbook.md`.

### Request body modes (`json`, `form`, `raw`)

By default endpoint and preflight `body` values are sent as JSON (`body_mode: json`).
Use `body_mode: form` for form-encoded payloads and `body_mode: raw` for raw string bodies.

```yaml
endpoints:
  - name: item-update-form
    path: /items/123
    method: POST
    body_mode: form
    victim_body:
      id: 123
    attacker_body:
      id: 123

  - name: item-update-raw
    path: /items/123
    method: POST
    body_mode: raw
    content_type: application/json
    victim_body: '{"id":123}'
    attacker_body: '{"id":123}'
```

Notes:

- `content_type` can be set for preflight/endpoint payloads, with per-role overrides on endpoints:
  - `victim_content_type`, `attacker_content_type`
- Endpoint defaults can be overridden per role:
  - `victim_body_mode`, `attacker_body_mode`
- Defaults when omitted:
  - `form` => `Content-Type: application/x-www-form-urlencoded`
  - `raw` => `Content-Type: text/plain; charset=utf-8`

## HTML report

```bash
python -m idor_lens report --in idor-report.jsonl --out idor-report.html
```

## Summarize JSONL

```bash
python -m idor_lens summarize --in idor-report.jsonl
```

## JUnit XML (CI)

```bash
python -m idor_lens junit --in idor-report.jsonl --out idor-report.junit.xml
```

## SARIF (GitHub code scanning)

```bash
python -m idor_lens sarif --in idor-report.jsonl --out idor-report.sarif
```

For GitHub Actions templates (fail-on-vuln, regression compare, SARIF upload), see `docs/ci-github-actions.md`.

## Regression compare

Compare a baseline run to a new run and fail CI only when *new* vulnerabilities appear:

```bash
python -m idor_lens compare --baseline baseline.jsonl --current idor-report.jsonl --fail-on-new
```
