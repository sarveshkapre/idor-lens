# Spec Cookbook

Copy/paste patterns for writing effective IDOR Lens specs.

## Secrets Via Env Vars

Keep tokens and session secrets out of `spec.yml`:

```yaml
victim:
  auth: Bearer ${VICTIM_TOKEN}
attacker:
  auth: Bearer ${ATTACKER_TOKEN}
```

Use `idor-lens validate --require-env` in CI to fail fast if variables are missing.

## Token Rotation Via auth_file

If your victim/attacker credentials expire during a long scan, read the Authorization header value from a file:

```yaml
victim:
  auth_file: /path/to/victim_auth.txt
attacker:
  auth_file: /path/to/attacker_auth.txt
```

The file contents should be the full header value (for example: `Bearer eyJ...`). IDOR Lens reads the file for
each request, so an external process can refresh tokens while the scan is running.

## Cookie Auth And Bootstrap (Preflight)

If your app needs cookies, CSRF, or a bootstrap request before protected endpoints behave normally:

```yaml
victim:
  cookies:
    session: ${VICTIM_SESSION}
  preflight:
    - path: /bootstrap
      method: GET
attacker:
  cookies:
    session: ${ATTACKER_SESSION}
  preflight:
    - path: /bootstrap
      method: GET
```

Preflight runs once per role using a persistent cookie jar, before endpoints are tested.

## CSRF Preflight With Form Payload

```yaml
victim:
  preflight:
    - path: /csrf
      method: POST
      body_mode: form
      body:
        seed: "1"
```

## Proxy Through Burp Or mitmproxy

```yaml
proxy: http://127.0.0.1:8080
```

Or pass it on the command line:

```bash
python -m idor_lens run --spec spec.yml --proxy http://127.0.0.1:8080
```

## Non-JSON Request Bodies

Form payload:

```yaml
endpoints:
  - name: item-update
    path: /items/123
    method: POST
    body_mode: form
    victim_body:
      id: 123
    attacker_body:
      id: 123
```

Raw payload:

```yaml
endpoints:
  - name: item-update-raw
    path: /items/123
    method: POST
    body_mode: raw
    content_type: application/json
    victim_body: '{"id":123}'
    attacker_body: '{"id":123}'
```

## Endpoint Matrix Expansion (Intruder-Style ID Substitution)

Use `matrix` + `{{var}}` placeholders to run one endpoint definition across many IDs:

```yaml
endpoints:
  - name: item-read-{{item_id}}-{{owner}}
    path: /items/{{item_id}}?owner={{owner}}
    method: POST
    victim_body:
      id: "{{item_id}}"
      owner: "{{owner}}"
    attacker_body:
      id: "{{item_id}}"
      owner: "{{owner}}"
    matrix:
      item_id: [101, 102]
      owner: [alice, bob]
```

Behavior notes:
- Expansion is cartesian product (`2 x 2 => 4` endpoint runs).
- Variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`.
- Findings include `matrix_values` for per-variant triage and compare/summarize key stability.

## Deny Heuristics For 2xx Denial Pages

Some targets return a 2xx "access denied" page. Use deny heuristics to avoid status-only false positives:

```yaml
deny_contains:
  - access denied
deny_regex:
  - "(?i)not authorized"
```

You can also set these per endpoint.

## Allow Heuristics To Reduce Status-Only False Positives

Some targets return a 2xx denial page that is hard to capture with deny heuristics alone. If you can fingerprint a
"real allowed" response, set allow heuristics:

```yaml
allow_contains:
  - "\"secret\""
allow_regex:
  - "\"owner\"\\s*:\\s*\"[^\"]+\""
```

When allow heuristics are set, a role is treated as "allowed" only when `2xx AND allow_match AND NOT deny_match`.

## Strict Body Matching With Dynamic JSON Fields

Use `--strict-body-match` to only flag a vulnerability when the attacker response body matches the victim response body.

For JSON responses that include known-dynamic fields (timestamps, request IDs), ignore them:

```yaml
json_ignore_paths:
  - /updatedAt
  - /requestId
  - /items/*/updatedAt
```

Path formats:
- JSON pointer: `"/a/b/0"`
- Dot + brackets: `"a.b[0]"`, `"items[*].updatedAt"`

## Retries, Backoff, And Timeouts

```yaml
retries: 2
retry_backoff_s: 0.25

victim:
  timeout: 10
attacker:
  timeout: 10

endpoints:
  - path: /items/123
    timeout: 15
```
