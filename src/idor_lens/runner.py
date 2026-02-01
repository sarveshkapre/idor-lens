from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml


_DEFAULT_MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Finding:
    endpoint: str
    method: str
    url: str
    victim_status: int
    attacker_status: int
    victim_elapsed_ms: int
    attacker_elapsed_ms: int
    vulnerable: bool
    confidence: str
    body_match: bool
    reason: str
    elapsed_ms: int
    victim_bytes: int
    attacker_bytes: int
    victim_sha256: str | None
    attacker_sha256: str | None
    victim_truncated: bool
    attacker_truncated: bool
    victim_error: str | None
    attacker_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "url": self.url,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "victim_elapsed_ms": self.victim_elapsed_ms,
            "attacker_elapsed_ms": self.attacker_elapsed_ms,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "body_match": self.body_match,
            "reason": self.reason,
            "elapsed_ms": self.elapsed_ms,
            "victim_bytes": self.victim_bytes,
            "attacker_bytes": self.attacker_bytes,
            "victim_sha256": self.victim_sha256,
            "attacker_sha256": self.attacker_sha256,
            "victim_truncated": self.victim_truncated,
            "attacker_truncated": self.attacker_truncated,
            "victim_error": self.victim_error,
            "attacker_error": self.attacker_error,
        }


def _load_spec(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("spec must be a YAML mapping")
    return data


def _as_str_dict(value: Any, *, name: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SystemExit(f"{name} must be a mapping of string->string")
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SystemExit(f"{name} must be a mapping of string->string")
        out[k] = v
    return out


def _headers(token: str | None, extra: dict[str, str]) -> dict[str, str]:
    headers = dict(extra)
    if token:
        headers["Authorization"] = token
    return headers


@dataclass(frozen=True)
class _Proof:
    status: int
    elapsed_ms: int
    num_bytes: int
    sha256: str | None
    truncated: bool
    error: str | None


def _request_with_proof(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: Any,
    timeout: float,
    max_bytes: int,
) -> _Proof:
    start = time.time()
    try:
        resp = requests.request(method, url, headers=headers, json=json_body, timeout=timeout)
    except requests.RequestException as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return _Proof(
            status=0,
            elapsed_ms=elapsed_ms,
            num_bytes=0,
            sha256=None,
            truncated=False,
            error=str(exc),
        )

    elapsed_ms = int((time.time() - start) * 1000)
    body = getattr(resp, "content", b"") or b""
    if not isinstance(body, (bytes, bytearray)):
        body = str(body).encode("utf-8", errors="replace")

    num_bytes = len(body)
    truncated = num_bytes > max_bytes
    digest = hashlib.sha256(body[:max_bytes]).hexdigest() if num_bytes else None

    return _Proof(
        status=int(getattr(resp, "status_code", 0)),
        elapsed_ms=elapsed_ms,
        num_bytes=num_bytes,
        sha256=digest,
        truncated=truncated,
        error=None,
    )


def run_test(
    spec_path: Path,
    out_path: Path,
    timeout: float,
    *,
    strict_body_match: bool = False,
    fail_on_vuln: bool = False,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> int:
    spec = _load_spec(spec_path)
    base_url = spec.get("base_url")
    if not base_url:
        raise SystemExit("missing base_url in spec")
    if not isinstance(base_url, str):
        raise SystemExit("base_url must be a string")

    victim = spec.get("victim", {})
    if not isinstance(victim, dict):
        raise SystemExit("victim must be a mapping")

    attacker = spec.get("attacker", {})
    if not isinstance(attacker, dict):
        raise SystemExit("attacker must be a mapping")

    endpoints = spec.get("endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        raise SystemExit("spec must include endpoints list")

    if max_bytes <= 0:
        raise SystemExit("--max-bytes must be > 0")

    is_stdout = str(out_path) == "-"
    if not is_stdout:
        out_path.parent.mkdir(parents=True, exist_ok=True)

    found_vulns = 0
    total = 0

    out_handle = None if is_stdout else out_path.open("w", encoding="utf-8")
    try:
        out = out_handle if out_handle is not None else sys.stdout
        for ep in endpoints:
            if not isinstance(ep, dict):
                raise SystemExit("each endpoints[] entry must be a mapping")
            path = ep.get("path", "/")
            if not isinstance(path, str):
                raise SystemExit("endpoint path must be a string")
            method = ep.get("method", "GET")
            if not isinstance(method, str):
                raise SystemExit("endpoint method must be a string")
            method = method.upper()

            victim_token = victim.get("auth")
            attacker_token = attacker.get("auth")
            if victim_token is not None and not isinstance(victim_token, str):
                raise SystemExit("victim.auth must be a string")
            if attacker_token is not None and not isinstance(attacker_token, str):
                raise SystemExit("attacker.auth must be a string")

            victim_headers = _headers(
                victim_token, _as_str_dict(victim.get("headers"), name="victim.headers")
            )
            attacker_headers = _headers(
                attacker_token, _as_str_dict(attacker.get("headers"), name="attacker.headers")
            )
            victim_body = ep.get("victim_body")
            attacker_body = ep.get("attacker_body", victim_body)

            url = urljoin(base_url, path)
            start_total = time.time()
            v = _request_with_proof(
                method,
                url,
                headers=victim_headers,
                json_body=victim_body,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            a = _request_with_proof(
                method,
                url,
                headers=attacker_headers,
                json_body=attacker_body,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            elapsed = int((time.time() - start_total) * 1000)

            victim_ok = 200 <= v.status < 300
            attacker_ok = 200 <= a.status < 300
            body_match = (
                v.sha256 is not None
                and v.sha256 == a.sha256
                and v.num_bytes == a.num_bytes
                and not (v.truncated or a.truncated)
            )

            vulnerable_by_status = victim_ok and attacker_ok
            vulnerable = vulnerable_by_status and (body_match if strict_body_match else True)

            confidence = (
                "high" if vulnerable and body_match else ("medium" if vulnerable else "none")
            )
            if v.error or a.error:
                confidence = "none"

            if v.error:
                reason = f"victim request error: {v.error}"
            elif a.error:
                reason = f"attacker request error: {a.error}"
            elif not victim_ok:
                reason = "victim not 2xx; cannot assess"
            elif not attacker_ok:
                reason = "attacker denied"
            elif strict_body_match and not body_match:
                reason = "attacker 2xx but response body differs (strict mode)"
            elif body_match:
                reason = "attacker 2xx with matching response body"
            else:
                reason = "attacker 2xx (status-only signal)"

            total += 1
            if vulnerable:
                found_vulns += 1

            finding = Finding(
                endpoint=path,
                method=method,
                url=url,
                victim_status=v.status,
                attacker_status=a.status,
                victim_elapsed_ms=v.elapsed_ms,
                attacker_elapsed_ms=a.elapsed_ms,
                vulnerable=vulnerable,
                confidence=confidence,
                body_match=body_match,
                reason=reason,
                elapsed_ms=elapsed,
                victim_bytes=v.num_bytes,
                attacker_bytes=a.num_bytes,
                victim_sha256=v.sha256,
                attacker_sha256=a.sha256,
                victim_truncated=v.truncated,
                attacker_truncated=a.truncated,
                victim_error=v.error,
                attacker_error=a.error,
            )
            out.write(json.dumps(finding.to_dict()) + "\n")
    finally:
        if out_handle is not None:
            out_handle.close()

    out_label = "stdout" if is_stdout else str(out_path)
    print(f"wrote {out_label} ({found_vulns}/{total} vulnerable)")
    return 2 if (fail_on_vuln and found_vulns) else 0
