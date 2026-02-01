from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

import requests
import yaml


_DEFAULT_MAX_BYTES = 1024 * 1024
_DEFAULT_RETRY_STATUSES = {429, 502, 503, 504}


def _merge_headers(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    if not extra:
        return dict(base)
    merged = dict(base)
    merged.update(extra)
    return merged


@dataclass(frozen=True)
class Finding:
    endpoint: str
    method: str
    url: str
    victim_status: int
    attacker_status: int
    victim_elapsed_ms: int
    attacker_elapsed_ms: int
    victim_attempts: int
    attacker_attempts: int
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
            "victim_attempts": self.victim_attempts,
            "attacker_attempts": self.attacker_attempts,
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
    expanded = _expand_env(data)
    if not isinstance(expanded, dict):
        raise SystemExit("spec must be a YAML mapping")
    return cast(dict[str, Any], expanded)


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


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


def _as_bool(value: Any, *, name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise SystemExit(f"{name} must be a boolean")


def _as_int(value: Any, *, name: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    raise SystemExit(f"{name} must be an integer")


def _as_float(value: Any, *, name: str, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    raise SystemExit(f"{name} must be a number")


def _as_int_set(value: Any, *, name: str, default: set[int]) -> set[int]:
    if value is None:
        return set(default)
    if not isinstance(value, list):
        raise SystemExit(f"{name} must be a list of integers")
    out: set[int] = set()
    for v in value:
        if not isinstance(v, int):
            raise SystemExit(f"{name} must be a list of integers")
        out.add(v)
    return out


def _as_optional_str(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise SystemExit(f"{name} must be a string")


def _proxies(proxy: str | None) -> dict[str, str] | None:
    if proxy is None:
        return None
    p = proxy.strip()
    if not p:
        return None
    return {"http": p, "https": p}


@dataclass(frozen=True)
class _Proof:
    status: int
    elapsed_ms: int
    num_bytes: int
    sha256: str | None
    truncated: bool
    error: str | None
    attempts: int


def _request_with_proof(
    request_fn: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: Any,
    timeout: float,
    max_bytes: int,
    verify_tls: bool,
    proxy: str | None,
    follow_redirects: bool,
    retries: int,
    retry_backoff_s: float,
    retry_statuses: set[int],
) -> _Proof:
    start = time.time()
    proxies = _proxies(proxy)

    last_error: str | None = None
    last_status = 0
    last_body: bytes = b""
    attempts_used = 0

    max_attempts = retries + 1
    for attempt in range(1, max_attempts + 1):
        attempts_used = attempt
        try:
            resp = request_fn(
                method,
                url,
                headers=headers,
                json=json_body,
                timeout=timeout,
                verify=verify_tls,
                proxies=proxies,
                allow_redirects=follow_redirects,
            )
            last_status = int(getattr(resp, "status_code", 0))
            body = getattr(resp, "content", b"") or b""
            if not isinstance(body, (bytes, bytearray)):
                body = str(body).encode("utf-8", errors="replace")
            last_body = bytes(body)
            last_error = None

            should_retry = attempt < max_attempts and last_status in retry_statuses
            if should_retry:
                if retry_backoff_s > 0:
                    time.sleep(retry_backoff_s * (2 ** (attempt - 1)))
                continue
            break
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                if retry_backoff_s > 0:
                    time.sleep(retry_backoff_s * (2 ** (attempt - 1)))
                continue
            break
        except requests.RequestException as exc:
            last_error = str(exc)
            break

    elapsed_ms = int((time.time() - start) * 1000)
    num_bytes = len(last_body)
    truncated = num_bytes > max_bytes
    digest = hashlib.sha256(last_body[:max_bytes]).hexdigest() if num_bytes else None

    return _Proof(
        status=last_status,
        elapsed_ms=elapsed_ms,
        num_bytes=num_bytes,
        sha256=digest,
        truncated=truncated,
        error=last_error,
        attempts=attempts_used,
    )


def _apply_cookies(session: requests.Session, cookies: dict[str, str], *, name: str) -> None:
    for k, v in cookies.items():
        if not k:
            raise SystemExit(f"{name}.cookies keys must be non-empty strings")
        session.cookies.set(k, v)


def _run_preflight(
    session: requests.Session,
    *,
    name: str,
    base_url: str,
    base_headers: dict[str, str],
    preflight: Any,
    timeout: float,
    max_bytes: int,
    verify_tls: bool,
    proxy: str | None,
    follow_redirects: bool,
    retries: int,
    retry_backoff_s: float,
    retry_statuses: set[int],
) -> None:
    if preflight is None:
        return
    if not isinstance(preflight, list):
        raise SystemExit(f"{name}.preflight must be a list")

    for idx, step in enumerate(preflight, start=1):
        if not isinstance(step, dict):
            raise SystemExit(f"{name}.preflight[{idx}] must be a mapping")
        path = step.get("path")
        if not isinstance(path, str) or not path:
            raise SystemExit(f"{name}.preflight[{idx}].path must be a non-empty string")
        method = step.get("method", "GET")
        if not isinstance(method, str) or not method:
            raise SystemExit(f"{name}.preflight[{idx}].method must be a non-empty string")

        step_timeout = step.get("timeout", timeout)
        if not isinstance(step_timeout, (int, float)):
            raise SystemExit(f"{name}.preflight[{idx}].timeout must be a number")

        step_headers = _merge_headers(
            base_headers,
            _as_str_dict(step.get("headers"), name=f"{name}.preflight[{idx}].headers"),
        )
        body = step.get("body")
        url = urljoin(base_url, path)

        proof = _request_with_proof(
            session.request,
            method.upper(),
            url,
            headers=step_headers,
            json_body=body,
            timeout=float(step_timeout),
            max_bytes=max_bytes,
            verify_tls=verify_tls,
            proxy=proxy,
            follow_redirects=follow_redirects,
            retries=retries,
            retry_backoff_s=retry_backoff_s,
            retry_statuses=retry_statuses,
        )
        if proof.error:
            raise SystemExit(
                f"{name} preflight step {idx} failed ({method.upper()} {path}): {proof.error}"
            )


def run_test(
    spec_path: Path,
    out_path: Path,
    timeout: float,
    *,
    strict_body_match: bool = False,
    fail_on_vuln: bool = False,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    verify_tls: bool | None = None,
    proxy: str | None = None,
    follow_redirects: bool | None = None,
    retries: int | None = None,
    retry_backoff_s: float | None = None,
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

    spec_verify_tls = _as_bool(spec.get("verify_tls"), name="verify_tls", default=True)
    verify_tls_effective = spec_verify_tls if verify_tls is None else verify_tls

    spec_proxy = _as_optional_str(spec.get("proxy"), name="proxy")

    spec_follow_redirects = _as_bool(
        spec.get("follow_redirects"), name="follow_redirects", default=False
    )
    follow_redirects_effective = (
        spec_follow_redirects if follow_redirects is None else follow_redirects
    )

    spec_retries = _as_int(spec.get("retries"), name="retries", default=0)
    if spec_retries < 0:
        raise SystemExit("retries must be >= 0")
    retries_effective = spec_retries if retries is None else retries
    if retries_effective < 0:
        raise SystemExit("--retries must be >= 0")

    spec_retry_backoff_s = _as_float(
        spec.get("retry_backoff_s"), name="retry_backoff_s", default=0.25
    )
    if spec_retry_backoff_s < 0:
        raise SystemExit("retry_backoff_s must be >= 0")
    retry_backoff_s_effective = spec_retry_backoff_s if retry_backoff_s is None else retry_backoff_s
    if retry_backoff_s_effective < 0:
        raise SystemExit("--retry-backoff must be >= 0")

    retry_statuses = _as_int_set(
        spec.get("retry_statuses"),
        name="retry_statuses",
        default=_DEFAULT_RETRY_STATUSES,
    )

    victim_token = victim.get("auth")
    attacker_token = attacker.get("auth")
    if victim_token is not None and not isinstance(victim_token, str):
        raise SystemExit("victim.auth must be a string")
    if attacker_token is not None and not isinstance(attacker_token, str):
        raise SystemExit("attacker.auth must be a string")

    victim_headers_base = _headers(
        victim_token, _as_str_dict(victim.get("headers"), name="victim.headers")
    )
    attacker_headers_base = _headers(
        attacker_token, _as_str_dict(attacker.get("headers"), name="attacker.headers")
    )
    victim_cookies = _as_str_dict(victim.get("cookies"), name="victim.cookies")
    attacker_cookies = _as_str_dict(attacker.get("cookies"), name="attacker.cookies")

    victim_timeout_default = _as_float(
        victim.get("timeout"), name="victim.timeout", default=float(timeout)
    )
    attacker_timeout_default = _as_float(
        attacker.get("timeout"), name="attacker.timeout", default=float(timeout)
    )
    if victim_timeout_default <= 0 or attacker_timeout_default <= 0:
        raise SystemExit("victim/attacker.timeout must be > 0")

    victim_verify_tls = _as_bool(
        victim.get("verify_tls"), name="victim.verify_tls", default=verify_tls_effective
    )
    attacker_verify_tls = _as_bool(
        attacker.get("verify_tls"), name="attacker.verify_tls", default=verify_tls_effective
    )

    victim_follow_redirects = _as_bool(
        victim.get("follow_redirects"),
        name="victim.follow_redirects",
        default=follow_redirects_effective,
    )
    attacker_follow_redirects = _as_bool(
        attacker.get("follow_redirects"),
        name="attacker.follow_redirects",
        default=follow_redirects_effective,
    )

    victim_retries = _as_int(
        victim.get("retries"), name="victim.retries", default=retries_effective
    )
    attacker_retries = _as_int(
        attacker.get("retries"), name="attacker.retries", default=retries_effective
    )
    if victim_retries < 0 or attacker_retries < 0:
        raise SystemExit("victim/attacker.retries must be >= 0")

    victim_retry_backoff_s = _as_float(
        victim.get("retry_backoff_s"),
        name="victim.retry_backoff_s",
        default=retry_backoff_s_effective,
    )
    attacker_retry_backoff_s = _as_float(
        attacker.get("retry_backoff_s"),
        name="attacker.retry_backoff_s",
        default=retry_backoff_s_effective,
    )
    if victim_retry_backoff_s < 0 or attacker_retry_backoff_s < 0:
        raise SystemExit("victim/attacker.retry_backoff_s must be >= 0")

    victim_proxy = _as_optional_str(victim.get("proxy"), name="victim.proxy") or spec_proxy
    attacker_proxy = _as_optional_str(attacker.get("proxy"), name="attacker.proxy") or spec_proxy
    if proxy is not None:
        victim_proxy = proxy
        attacker_proxy = proxy

    victim_session = requests.Session()
    attacker_session = requests.Session()
    _apply_cookies(victim_session, victim_cookies, name="victim")
    _apply_cookies(attacker_session, attacker_cookies, name="attacker")
    _run_preflight(
        victim_session,
        name="victim",
        base_url=base_url,
        base_headers=victim_headers_base,
        preflight=victim.get("preflight"),
        timeout=timeout,
        max_bytes=max_bytes,
        verify_tls=victim_verify_tls,
        proxy=victim_proxy,
        follow_redirects=victim_follow_redirects,
        retries=victim_retries,
        retry_backoff_s=victim_retry_backoff_s,
        retry_statuses=retry_statuses,
    )
    _run_preflight(
        attacker_session,
        name="attacker",
        base_url=base_url,
        base_headers=attacker_headers_base,
        preflight=attacker.get("preflight"),
        timeout=timeout,
        max_bytes=max_bytes,
        verify_tls=attacker_verify_tls,
        proxy=attacker_proxy,
        follow_redirects=attacker_follow_redirects,
        retries=attacker_retries,
        retry_backoff_s=attacker_retry_backoff_s,
        retry_statuses=retry_statuses,
    )

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

            common_headers = _as_str_dict(ep.get("headers"), name=f"endpoints[{total + 1}].headers")
            victim_headers = _merge_headers(
                _merge_headers(victim_headers_base, common_headers),
                _as_str_dict(
                    ep.get("victim_headers"), name=f"endpoints[{total + 1}].victim_headers"
                ),
            )
            attacker_headers = _merge_headers(
                _merge_headers(attacker_headers_base, common_headers),
                _as_str_dict(
                    ep.get("attacker_headers"), name=f"endpoints[{total + 1}].attacker_headers"
                ),
            )
            victim_body = ep.get("victim_body")
            attacker_body = ep.get("attacker_body", victim_body)

            victim_timeout = victim_timeout_default
            attacker_timeout = attacker_timeout_default

            ep_timeout_raw = ep.get("timeout")
            if ep_timeout_raw is not None:
                ep_timeout = _as_float(
                    ep_timeout_raw, name=f"endpoints[{total + 1}].timeout", default=float(timeout)
                )
                if ep_timeout <= 0:
                    raise SystemExit(f"endpoints[{total + 1}].timeout must be > 0")
                victim_timeout = ep_timeout
                attacker_timeout = ep_timeout

            victim_timeout_raw = ep.get("victim_timeout")
            if victim_timeout_raw is not None:
                victim_timeout = _as_float(
                    victim_timeout_raw,
                    name=f"endpoints[{total + 1}].victim_timeout",
                    default=victim_timeout,
                )
                if victim_timeout <= 0:
                    raise SystemExit(f"endpoints[{total + 1}].victim_timeout must be > 0")

            attacker_timeout_raw = ep.get("attacker_timeout")
            if attacker_timeout_raw is not None:
                attacker_timeout = _as_float(
                    attacker_timeout_raw,
                    name=f"endpoints[{total + 1}].attacker_timeout",
                    default=attacker_timeout,
                )
                if attacker_timeout <= 0:
                    raise SystemExit(f"endpoints[{total + 1}].attacker_timeout must be > 0")

            ep_follow_redirects = _as_bool(
                ep.get("follow_redirects"),
                name=f"endpoints[{total + 1}].follow_redirects",
                default=follow_redirects_effective,
            )
            victim_ep_follow_redirects = _as_bool(
                ep.get("victim_follow_redirects"),
                name=f"endpoints[{total + 1}].victim_follow_redirects",
                default=ep_follow_redirects,
            )
            attacker_ep_follow_redirects = _as_bool(
                ep.get("attacker_follow_redirects"),
                name=f"endpoints[{total + 1}].attacker_follow_redirects",
                default=ep_follow_redirects,
            )

            url = urljoin(base_url, path)
            start_total = time.time()
            v = _request_with_proof(
                victim_session.request,
                method,
                url,
                headers=victim_headers,
                json_body=victim_body,
                timeout=victim_timeout,
                max_bytes=max_bytes,
                verify_tls=victim_verify_tls,
                proxy=victim_proxy,
                follow_redirects=victim_ep_follow_redirects,
                retries=victim_retries,
                retry_backoff_s=victim_retry_backoff_s,
                retry_statuses=retry_statuses,
            )
            a = _request_with_proof(
                attacker_session.request,
                method,
                url,
                headers=attacker_headers,
                json_body=attacker_body,
                timeout=attacker_timeout,
                max_bytes=max_bytes,
                verify_tls=attacker_verify_tls,
                proxy=attacker_proxy,
                follow_redirects=attacker_ep_follow_redirects,
                retries=attacker_retries,
                retry_backoff_s=attacker_retry_backoff_s,
                retry_statuses=retry_statuses,
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
                victim_attempts=v.attempts,
                attacker_attempts=a.attempts,
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
    print(f"wrote {out_label} ({found_vulns}/{total} vulnerable)", file=sys.stderr)
    return 2 if (fail_on_vuln and found_vulns) else 0
