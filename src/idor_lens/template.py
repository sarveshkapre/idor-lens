from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SpecTemplateOptions:
    base_url: str


def render_spec_template(opts: SpecTemplateOptions) -> str:
    # Keep this template intentionally small and copy/paste-friendly.
    return f"""# IDOR Lens spec
# - Strings support env var expansion: $VAR / ${{VAR}}
# - Recommended: keep secrets in env vars, not in this file.

base_url: {opts.base_url}

# Optional: set to false for self-signed/local targets.
verify_tls: true

# Optional: route requests via Burp/mitmproxy.
# proxy: http://127.0.0.1:8080

# Optional: retries for transient errors (default: 0).
# retries: 0
# retry_backoff_s: 0.25

victim:
  # Typical header-based auth:
  auth: Bearer ${{VICTIM_TOKEN}}
  # Or supply extra headers:
  # headers:
  #   X-CSRF: ${{VICTIM_CSRF}}

  # Optional default request timeout (seconds):
  # timeout: 10

  # Optional cookie jar (string->string):
  # cookies:
  #   session: ${{VICTIM_SESSION}}

  # Optional bootstrap requests (persisted cookies):
  # preflight:
  #   - path: /bootstrap
  #     method: GET

attacker:
  auth: Bearer ${{ATTACKER_TOKEN}}
  # timeout: 10

endpoints:
  - path: /items/123
    method: GET
    # timeout: 10
    # victim_timeout: 10
    # attacker_timeout: 10
    # Optional per-endpoint headers:
    # headers:
    #   Accept: application/json
    #
    # Optional per-role headers:
    # victim_headers:
    #   X-Request-ID: victim-req
    # attacker_headers:
    #   X-Request-ID: attacker-req
    #
    # Optional request bodies (for POST/PUT/etc):
    # victim_body:
    #   id: 123
    # attacker_body:
    #   id: 123
"""
