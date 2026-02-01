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
  - path: /items/123
    method: GET
```

Tips:

- Prefer env vars for secrets (strings support `$VAR` / `${VAR}` expansion):
  - `auth: Bearer ${VICTIM_TOKEN}`
- Use `--proxy http://127.0.0.1:8080` to route both roles through Burp/mitmproxy.
- Use `--insecure` for self-signed TLS (e.g. local dev).
- By default redirects are not followed; use `--follow-redirects` if needed.
- For flaky targets, use `--retries 2 --retry-backoff 0.25` (retries 429/502/503/504 + timeouts).
- Use `--out -` to stream JSONL to stdout.
- Use `--fail-on-vuln` for CI/regression.
- Use `--strict-body-match` to reduce false positives when attacker gets a different 2xx body.

## HTML report

```bash
python -m idor_lens report --in idor-report.jsonl --out idor-report.html
```

## Regression compare

Compare a baseline run to a new run and fail CI only when *new* vulnerabilities appear:

```bash
python -m idor_lens compare --baseline baseline.jsonl --current idor-report.jsonl --fail-on-new
```
