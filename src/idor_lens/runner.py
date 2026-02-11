from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from .matrix import expand_endpoints
from .json_paths import apply_ignore_paths
from .spec import load_spec


_DEFAULT_MAX_BYTES = 1024 * 1024
_DEFAULT_RETRY_STATUSES = {429, 502, 503, 504}
_BODY_MODE_JSON = "json"
_BODY_MODE_FORM = "form"
_BODY_MODE_RAW = "raw"
_BODY_MODES = {_BODY_MODE_JSON, _BODY_MODE_FORM, _BODY_MODE_RAW}


def _merge_str_maps(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    if not extra:
        return dict(base)
    merged = dict(base)
    merged.update(extra)
    return merged


def _merge_headers(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    return _merge_str_maps(base, extra)


@dataclass(frozen=True)
class Finding:
    endpoint: str
    name: str | None
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
    victim_deny_match: bool
    attacker_deny_match: bool
    victim_allow_match: bool | None
    attacker_allow_match: bool | None
    victim_response_capped: bool
    attacker_response_capped: bool
    matrix_values: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "name": self.name,
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
            "victim_deny_match": self.victim_deny_match,
            "attacker_deny_match": self.attacker_deny_match,
            "victim_allow_match": self.victim_allow_match,
            "attacker_allow_match": self.attacker_allow_match,
            "victim_response_capped": self.victim_response_capped,
            "attacker_response_capped": self.attacker_response_capped,
            "matrix_values": self.matrix_values,
        }


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
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise SystemExit(f"{name} must be an integer")


def _as_float(value: Any, *, name: str, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    raise SystemExit(f"{name} must be a number")


def _as_int_set(value: Any, *, name: str, default: set[int]) -> set[int]:
    if value is None:
        return set(default)
    if not isinstance(value, list):
        raise SystemExit(f"{name} must be a list of integers")
    out: set[int] = set()
    for v in value:
        if not isinstance(v, int) or isinstance(v, bool):
            raise SystemExit(f"{name} must be a list of integers")
        out.add(v)
    return out


def _as_optional_str(value: Any, *, name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise SystemExit(f"{name} must be a string")


def _as_optional_non_empty_str(value: Any, *, name: str) -> str | None:
    parsed = _as_optional_str(value, name=name)
    if parsed is None:
        return None
    if not parsed:
        raise SystemExit(f"{name} must be a non-empty string")
    return parsed


def _as_str_list(value: Any, *, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SystemExit(f"{name} must be a list of strings")
    out: list[str] = []
    for v in value:
        if not isinstance(v, str) or not v:
            raise SystemExit(f"{name} must be a list of non-empty strings")
        out.append(v)
    return out


def _as_regex_list(value: Any, *, name: str) -> list[re.Pattern[str]]:
    patterns = _as_str_list(value, name=name)
    compiled: list[re.Pattern[str]] = []
    for idx, p in enumerate(patterns, start=1):
        try:
            compiled.append(re.compile(p))
        except re.error as exc:
            raise SystemExit(f"{name}[{idx}] is not a valid regex: {exc}") from exc
    return compiled


def _as_body_mode(value: Any, *, name: str, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{name} must be one of: json, form, raw")
    normalized = value.lower()
    if normalized not in _BODY_MODES:
        raise SystemExit(f"{name} must be one of: json, form, raw")
    return normalized


def _proxies(proxy: str | None) -> dict[str, str] | None:
    if proxy is None:
        return None
    p = proxy.strip()
    if not p:
        return None
    return {"http": p, "https": p}


def _json_body_match(
    victim_sample: bytes, attacker_sample: bytes, ignore_paths: list[str]
) -> bool | None:
    v_norm = _normalize_json_sample(victim_sample, ignore_paths)
    if v_norm is None:
        return None
    a_norm = _normalize_json_sample(attacker_sample, ignore_paths)
    if a_norm is None:
        return None
    return v_norm == a_norm


def _normalize_json_sample(sample: bytes, ignore_paths: list[str]) -> str | None:
    # Best-effort: only attempt if it "looks like" JSON.
    stripped = sample.lstrip()
    if not stripped or stripped[:1] not in (b"{", b"["):
        return None

    try:
        obj = json.loads(sample.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None

    try:
        apply_ignore_paths(obj, ignore_paths)
    except ValueError as exc:
        raise SystemExit(f"invalid json_ignore_paths entry: {exc}") from exc

    # Canonicalize for stable comparisons across whitespace/key order.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class _Proof:
    status: int
    elapsed_ms: int
    num_bytes: int
    sha256: str | None
    truncated: bool
    sample: bytes
    error: str | None
    attempts: int
    deny_match: bool
    allow_match: bool
    response_capped: bool


@dataclass(frozen=True)
class _PreparedPayload:
    headers: dict[str, str]
    json_body: Any
    data_body: Any


def _has_header(headers: dict[str, str], name: str) -> bool:
    expected = name.lower()
    return any(k.lower() == expected for k in headers)


def _prepare_payload(
    *,
    headers: dict[str, str],
    body: Any,
    body_mode: str,
    content_type: str | None,
    name: str,
) -> _PreparedPayload:
    if body_mode not in _BODY_MODES:
        raise SystemExit(f"{name}.body_mode must be one of: json, form, raw")

    request_headers = dict(headers)
    default_content_type: str | None = None
    json_body: Any = None
    data_body: Any = None

    if body_mode == _BODY_MODE_JSON:
        json_body = body
    elif body_mode == _BODY_MODE_FORM:
        if body is not None and not isinstance(body, dict):
            raise SystemExit(f"{name}.body must be a mapping when body_mode=form")
        if isinstance(body, dict):
            for key in body:
                if not isinstance(key, str):
                    raise SystemExit(
                        f"{name}.body must be a mapping with string keys when body_mode=form"
                    )
        data_body = body
        default_content_type = "application/x-www-form-urlencoded"
    else:
        if body is not None and not isinstance(body, str):
            raise SystemExit(f"{name}.body must be a string when body_mode=raw")
        data_body = body
        default_content_type = "text/plain; charset=utf-8"

    effective_content_type = content_type or default_content_type
    if effective_content_type and not _has_header(request_headers, "Content-Type"):
        request_headers["Content-Type"] = effective_content_type

    return _PreparedPayload(
        headers=request_headers,
        json_body=json_body,
        data_body=data_body,
    )


def _request_with_proof(
    request_fn: Any,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    cookies: dict[str, str] | None,
    json_body: Any,
    data_body: Any,
    timeout: float,
    max_bytes: int,
    max_response_bytes: int | None,
    verify_tls: bool,
    proxy: str | None,
    follow_redirects: bool,
    retries: int,
    retry_backoff_s: float,
    retry_statuses: set[int],
    allow_contains: list[str],
    allow_regexes: list[re.Pattern[str]],
    deny_contains: list[str],
    deny_regexes: list[re.Pattern[str]],
) -> _Proof:
    start = time.time()
    proxies = _proxies(proxy)

    def _read_body_streaming(
        resp: Any, *, max_bytes: int, max_response_bytes: int | None
    ) -> tuple[int, bytes, bool]:
        # Prefer streaming reads to avoid buffering large bodies in memory.
        iter_content = getattr(resp, "iter_content", None)
        if callable(iter_content):
            sample_parts: list[bytes] = []
            sample_len = 0
            total = 0
            capped = False
            try:
                for chunk in iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    b = bytes(chunk)
                    if max_response_bytes is not None:
                        remaining = max_response_bytes - total
                        if remaining <= 0:
                            capped = True
                            break
                        if len(b) > remaining:
                            b = b[:remaining]
                            capped = True
                    total += len(b)
                    if sample_len < max_bytes:
                        take = b[: max_bytes - sample_len]
                        if take:
                            sample_parts.append(take)
                            sample_len += len(take)
            finally:
                close = getattr(resp, "close", None)
                if callable(close):
                    close()
            return total, b"".join(sample_parts), capped

        body = getattr(resp, "content", b"") or b""
        if not isinstance(body, (bytes, bytearray)):
            body = str(body).encode("utf-8", errors="replace")
        body_bytes = bytes(body)
        capped = False
        if max_response_bytes is not None and len(body_bytes) > max_response_bytes:
            body_bytes = body_bytes[:max_response_bytes]
            capped = True
        return len(body_bytes), body_bytes[:max_bytes], capped

    last_error: str | None = None
    last_status = 0
    last_sample: bytes = b""
    last_num_bytes = 0
    deny_match = False
    allow_match = False
    attempts_used = 0
    response_capped = False

    max_attempts = retries + 1
    for attempt in range(1, max_attempts + 1):
        attempts_used = attempt
        try:
            resp = request_fn(
                method,
                url,
                headers=headers,
                cookies=cookies,
                json=json_body,
                data=data_body,
                timeout=timeout,
                verify=verify_tls,
                proxies=proxies,
                allow_redirects=follow_redirects,
                stream=True,
            )
            last_status = int(getattr(resp, "status_code", 0))
            last_num_bytes, last_sample, response_capped = _read_body_streaming(
                resp, max_bytes=max_bytes, max_response_bytes=max_response_bytes
            )
            last_error = None
            deny_match = False
            allow_match = False

            if (allow_contains or allow_regexes or deny_contains or deny_regexes) and last_sample:
                # Only examine the first max_bytes since we already hash at most that much.
                text = last_sample.decode("utf-8", errors="replace")
                lower = text.lower()

                for needle in deny_contains:
                    if needle.lower() in lower:
                        deny_match = True
                        break
                if not deny_match:
                    for rx in deny_regexes:
                        if rx.search(text) is not None:
                            deny_match = True
                            break

                for needle in allow_contains:
                    if needle.lower() in lower:
                        allow_match = True
                        break
                if not allow_match:
                    for rx in allow_regexes:
                        if rx.search(text) is not None:
                            allow_match = True
                            break

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
    num_bytes = last_num_bytes
    truncated = num_bytes > max_bytes
    digest = hashlib.sha256(last_sample).hexdigest() if num_bytes else None

    return _Proof(
        status=last_status,
        elapsed_ms=elapsed_ms,
        num_bytes=num_bytes,
        sha256=digest,
        truncated=truncated,
        sample=last_sample,
        error=last_error,
        attempts=attempts_used,
        deny_match=deny_match,
        allow_match=allow_match,
        response_capped=response_capped,
    )


def _apply_cookies(session: requests.Session, cookies: dict[str, str], *, name: str) -> None:
    _validate_cookie_keys(cookies, name=name)
    for k, v in cookies.items():
        session.cookies.set(k, v)


def _validate_cookie_keys(cookies: dict[str, str], *, name: str) -> None:
    for k in cookies:
        if not k:
            raise SystemExit(f"{name}.cookies keys must be non-empty strings")


def _run_preflight(
    session: requests.Session,
    *,
    name: str,
    base_url: str,
    base_headers: dict[str, str],
    auth_token: str | None,
    preflight: Any,
    timeout: float,
    max_bytes: int,
    max_response_bytes: int | None,
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
        if auth_token and not _has_header(step_headers, "Authorization"):
            step_headers["Authorization"] = auth_token
        body = step.get("body")
        step_body_mode = _as_body_mode(
            step.get("body_mode"),
            name=f"{name}.preflight[{idx}].body_mode",
            default=_BODY_MODE_JSON,
        )
        step_content_type = _as_optional_non_empty_str(
            step.get("content_type"),
            name=f"{name}.preflight[{idx}].content_type",
        )
        payload = _prepare_payload(
            headers=step_headers,
            body=body,
            body_mode=step_body_mode,
            content_type=step_content_type,
            name=f"{name}.preflight[{idx}]",
        )
        url = urljoin(base_url, path)

        proof = _request_with_proof(
            session.request,
            method.upper(),
            url,
            headers=payload.headers,
            cookies=None,
            json_body=payload.json_body,
            data_body=payload.data_body,
            timeout=float(step_timeout),
            max_bytes=max_bytes,
            max_response_bytes=max_response_bytes,
            verify_tls=verify_tls,
            proxy=proxy,
            follow_redirects=follow_redirects,
            retries=retries,
            retry_backoff_s=retry_backoff_s,
            retry_statuses=retry_statuses,
            allow_contains=[],
            allow_regexes=[],
            deny_contains=[],
            deny_regexes=[],
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
    max_response_bytes: int | None = None,
    only_names: list[str] | None = None,
    only_paths: list[str] | None = None,
    verify_tls: bool | None = None,
    proxy: str | None = None,
    follow_redirects: bool | None = None,
    retries: int | None = None,
    retry_backoff_s: float | None = None,
) -> int:
    spec = load_spec(spec_path)
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

    endpoints_raw = spec.get("endpoints", [])
    if not isinstance(endpoints_raw, list) or not endpoints_raw:
        raise SystemExit("spec must include endpoints list")
    endpoints = expand_endpoints(endpoints_raw)

    if max_bytes <= 0:
        raise SystemExit("--max-bytes must be > 0")
    if max_response_bytes is not None and max_response_bytes <= 0:
        raise SystemExit("--max-response-bytes must be > 0")

    only_name_set: set[str] = set()
    only_path_set: set[str] = set()
    if only_names is not None:
        for idx, n in enumerate(only_names, start=1):
            if not isinstance(n, str) or not n:
                raise SystemExit(f"only_names[{idx}] must be a non-empty string")
            only_name_set.add(n)
    if only_paths is not None:
        for idx, p in enumerate(only_paths, start=1):
            if not isinstance(p, str) or not p:
                raise SystemExit(f"only_paths[{idx}] must be a non-empty string")
            only_path_set.add(p)

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

    spec_deny_contains = _as_str_list(spec.get("deny_contains"), name="deny_contains")
    spec_deny_regexes = _as_regex_list(spec.get("deny_regex"), name="deny_regex")
    spec_allow_contains = _as_str_list(spec.get("allow_contains"), name="allow_contains")
    spec_allow_regexes = _as_regex_list(spec.get("allow_regex"), name="allow_regex")
    spec_json_ignore_paths = _as_str_list(spec.get("json_ignore_paths"), name="json_ignore_paths")

    victim_token = _as_optional_non_empty_str(victim.get("auth"), name="victim.auth")
    attacker_token = _as_optional_non_empty_str(attacker.get("auth"), name="attacker.auth")
    victim_auth_file = _as_optional_non_empty_str(victim.get("auth_file"), name="victim.auth_file")
    attacker_auth_file = _as_optional_non_empty_str(
        attacker.get("auth_file"), name="attacker.auth_file"
    )
    if victim_token and victim_auth_file:
        raise SystemExit("victim must not set both auth and auth_file")
    if attacker_token and attacker_auth_file:
        raise SystemExit("attacker must not set both auth and auth_file")

    def _read_auth_file(path: str, *, role_name: str) -> str:
        try:
            data = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SystemExit(f"{role_name}.auth_file could not be read: {exc}") from exc
        token = data.strip()
        if not token:
            raise SystemExit(f"{role_name}.auth_file must not be empty")
        return token

    def _load_role_auth(*, role_name: str, static: str | None, file_path: str | None) -> str | None:
        if file_path:
            return _read_auth_file(file_path, role_name=role_name)
        return static

    victim_headers_base = _as_str_dict(victim.get("headers"), name="victim.headers")
    attacker_headers_base = _as_str_dict(attacker.get("headers"), name="attacker.headers")
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
        auth_token=_load_role_auth(
            role_name="victim", static=victim_token, file_path=victim_auth_file
        ),
        preflight=victim.get("preflight"),
        timeout=timeout,
        max_bytes=max_bytes,
        max_response_bytes=max_response_bytes,
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
        auth_token=_load_role_auth(
            role_name="attacker", static=attacker_token, file_path=attacker_auth_file
        ),
        preflight=attacker.get("preflight"),
        timeout=timeout,
        max_bytes=max_bytes,
        max_response_bytes=max_response_bytes,
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
    matched = 0

    out_handle = None if is_stdout else out_path.open("w", encoding="utf-8")
    try:
        out = out_handle if out_handle is not None else sys.stdout
        for idx, ep in enumerate(endpoints, start=1):
            path = ep.get("path")
            if not isinstance(path, str) or not path:
                raise SystemExit("endpoint path must be a non-empty string")
            name_raw = ep.get("name")
            if name_raw is not None and (not isinstance(name_raw, str) or not name_raw):
                raise SystemExit(f"endpoints[{idx}].name must be a non-empty string")
            endpoint_name = name_raw if isinstance(name_raw, str) else None

            if only_name_set and endpoint_name not in only_name_set:
                continue
            if only_path_set and path not in only_path_set:
                continue
            matched += 1

            method = ep.get("method", "GET")
            if not isinstance(method, str) or not method:
                raise SystemExit("endpoint method must be a non-empty string")
            method = method.upper()

            common_headers = _as_str_dict(ep.get("headers"), name=f"endpoints[{idx}].headers")
            victim_headers = _merge_headers(
                _merge_headers(victim_headers_base, common_headers),
                _as_str_dict(ep.get("victim_headers"), name=f"endpoints[{idx}].victim_headers"),
            )
            attacker_headers = _merge_headers(
                _merge_headers(attacker_headers_base, common_headers),
                _as_str_dict(ep.get("attacker_headers"), name=f"endpoints[{idx}].attacker_headers"),
            )
            common_cookies = _as_str_dict(ep.get("cookies"), name=f"endpoints[{idx}].cookies")
            victim_request_cookies = _merge_str_maps(
                common_cookies,
                _as_str_dict(ep.get("victim_cookies"), name=f"endpoints[{idx}].victim_cookies"),
            )
            attacker_request_cookies = _merge_str_maps(
                common_cookies,
                _as_str_dict(ep.get("attacker_cookies"), name=f"endpoints[{idx}].attacker_cookies"),
            )
            _validate_cookie_keys(victim_request_cookies, name=f"endpoints[{idx}].victim")
            _validate_cookie_keys(attacker_request_cookies, name=f"endpoints[{idx}].attacker")
            victim_body = ep.get("victim_body")
            attacker_body = ep.get("attacker_body", victim_body)
            endpoint_body_mode = _as_body_mode(
                ep.get("body_mode"),
                name=f"endpoints[{idx}].body_mode",
                default=_BODY_MODE_JSON,
            )
            victim_body_mode = _as_body_mode(
                ep.get("victim_body_mode"),
                name=f"endpoints[{idx}].victim_body_mode",
                default=endpoint_body_mode,
            )
            attacker_body_mode = _as_body_mode(
                ep.get("attacker_body_mode"),
                name=f"endpoints[{idx}].attacker_body_mode",
                default=victim_body_mode,
            )
            endpoint_content_type = _as_optional_non_empty_str(
                ep.get("content_type"),
                name=f"endpoints[{idx}].content_type",
            )
            victim_content_type = (
                _as_optional_non_empty_str(
                    ep.get("victim_content_type"),
                    name=f"endpoints[{idx}].victim_content_type",
                )
                or endpoint_content_type
            )
            attacker_content_type = (
                _as_optional_non_empty_str(
                    ep.get("attacker_content_type"),
                    name=f"endpoints[{idx}].attacker_content_type",
                )
                or victim_content_type
            )
            victim_payload = _prepare_payload(
                headers=victim_headers,
                body=victim_body,
                body_mode=victim_body_mode,
                content_type=victim_content_type,
                name=f"endpoints[{idx}].victim",
            )
            attacker_payload = _prepare_payload(
                headers=attacker_headers,
                body=attacker_body,
                body_mode=attacker_body_mode,
                content_type=attacker_content_type,
                name=f"endpoints[{idx}].attacker",
            )
            victim_req_headers = dict(victim_payload.headers)
            victim_auth = _load_role_auth(
                role_name="victim", static=victim_token, file_path=victim_auth_file
            )
            if victim_auth and not _has_header(victim_req_headers, "Authorization"):
                victim_req_headers["Authorization"] = victim_auth
            attacker_req_headers = dict(attacker_payload.headers)
            attacker_auth = _load_role_auth(
                role_name="attacker", static=attacker_token, file_path=attacker_auth_file
            )
            if attacker_auth and not _has_header(attacker_req_headers, "Authorization"):
                attacker_req_headers["Authorization"] = attacker_auth

            victim_timeout = victim_timeout_default
            attacker_timeout = attacker_timeout_default

            ep_timeout_raw = ep.get("timeout")
            if ep_timeout_raw is not None:
                ep_timeout = _as_float(
                    ep_timeout_raw, name=f"endpoints[{idx}].timeout", default=float(timeout)
                )
                if ep_timeout <= 0:
                    raise SystemExit(f"endpoints[{idx}].timeout must be > 0")
                victim_timeout = ep_timeout
                attacker_timeout = ep_timeout

            victim_timeout_raw = ep.get("victim_timeout")
            if victim_timeout_raw is not None:
                victim_timeout = _as_float(
                    victim_timeout_raw,
                    name=f"endpoints[{idx}].victim_timeout",
                    default=victim_timeout,
                )
                if victim_timeout <= 0:
                    raise SystemExit(f"endpoints[{idx}].victim_timeout must be > 0")

            attacker_timeout_raw = ep.get("attacker_timeout")
            if attacker_timeout_raw is not None:
                attacker_timeout = _as_float(
                    attacker_timeout_raw,
                    name=f"endpoints[{idx}].attacker_timeout",
                    default=attacker_timeout,
                )
                if attacker_timeout <= 0:
                    raise SystemExit(f"endpoints[{idx}].attacker_timeout must be > 0")

            ep_follow_redirects = _as_bool(
                ep.get("follow_redirects"),
                name=f"endpoints[{idx}].follow_redirects",
                default=follow_redirects_effective,
            )
            victim_ep_follow_redirects = _as_bool(
                ep.get("victim_follow_redirects"),
                name=f"endpoints[{idx}].victim_follow_redirects",
                default=ep_follow_redirects,
            )
            attacker_ep_follow_redirects = _as_bool(
                ep.get("attacker_follow_redirects"),
                name=f"endpoints[{idx}].attacker_follow_redirects",
                default=ep_follow_redirects,
            )

            ep_deny_contains = _as_str_list(
                ep.get("deny_contains"), name=f"endpoints[{idx}].deny_contains"
            )
            ep_deny_regexes = _as_regex_list(
                ep.get("deny_regex"), name=f"endpoints[{idx}].deny_regex"
            )
            deny_contains = [*spec_deny_contains, *ep_deny_contains]
            deny_regexes = [*spec_deny_regexes, *ep_deny_regexes]
            ep_allow_contains = _as_str_list(
                ep.get("allow_contains"), name=f"endpoints[{idx}].allow_contains"
            )
            ep_allow_regexes = _as_regex_list(
                ep.get("allow_regex"), name=f"endpoints[{idx}].allow_regex"
            )
            allow_contains = [*spec_allow_contains, *ep_allow_contains]
            allow_regexes = [*spec_allow_regexes, *ep_allow_regexes]
            allow_required = bool(allow_contains or allow_regexes)
            ep_json_ignore_paths = _as_str_list(
                ep.get("json_ignore_paths"), name=f"endpoints[{idx}].json_ignore_paths"
            )
            json_ignore_paths = [*spec_json_ignore_paths, *ep_json_ignore_paths]

            url = urljoin(base_url, path)
            start_total = time.time()
            v = _request_with_proof(
                victim_session.request,
                method,
                url,
                headers=victim_req_headers,
                cookies=(victim_request_cookies or None),
                json_body=victim_payload.json_body,
                data_body=victim_payload.data_body,
                timeout=victim_timeout,
                max_bytes=max_bytes,
                max_response_bytes=max_response_bytes,
                verify_tls=victim_verify_tls,
                proxy=victim_proxy,
                follow_redirects=victim_ep_follow_redirects,
                retries=victim_retries,
                retry_backoff_s=victim_retry_backoff_s,
                retry_statuses=retry_statuses,
                allow_contains=allow_contains,
                allow_regexes=allow_regexes,
                deny_contains=deny_contains,
                deny_regexes=deny_regexes,
            )
            a = _request_with_proof(
                attacker_session.request,
                method,
                url,
                headers=attacker_req_headers,
                cookies=(attacker_request_cookies or None),
                json_body=attacker_payload.json_body,
                data_body=attacker_payload.data_body,
                timeout=attacker_timeout,
                max_bytes=max_bytes,
                max_response_bytes=max_response_bytes,
                verify_tls=attacker_verify_tls,
                proxy=attacker_proxy,
                follow_redirects=attacker_ep_follow_redirects,
                retries=attacker_retries,
                retry_backoff_s=attacker_retry_backoff_s,
                retry_statuses=retry_statuses,
                allow_contains=allow_contains,
                allow_regexes=allow_regexes,
                deny_contains=deny_contains,
                deny_regexes=deny_regexes,
            )
            elapsed = int((time.time() - start_total) * 1000)

            victim_2xx = 200 <= v.status < 300
            attacker_2xx = 200 <= a.status < 300
            victim_ok = (
                victim_2xx and not v.deny_match and (v.allow_match if allow_required else True)
            )
            attacker_ok = (
                attacker_2xx and not a.deny_match and (a.allow_match if allow_required else True)
            )
            body_match = (
                v.num_bytes == 0
                and a.num_bytes == 0
                and not (v.truncated or a.truncated)
                and not (v.response_capped or a.response_capped)
                and not (v.error or a.error)
            ) or (
                v.sha256 is not None
                and v.sha256 == a.sha256
                and v.num_bytes == a.num_bytes
                and not (v.truncated or a.truncated)
                and not (v.response_capped or a.response_capped)
            )
            if (
                json_ignore_paths
                and not (v.truncated or a.truncated)
                and not (v.response_capped or a.response_capped)
                and v.sample
                and a.sample
            ):
                json_match = _json_body_match(v.sample, a.sample, json_ignore_paths)
                if json_match is not None:
                    body_match = json_match

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
            elif not victim_2xx:
                reason = "victim not 2xx; cannot assess"
            elif v.deny_match and a.deny_match:
                reason = "both roles matched deny heuristics; cannot assess"
            elif v.deny_match:
                reason = "victim matched deny heuristics; cannot assess"
            elif allow_required and not v.allow_match:
                reason = "victim did not match allow heuristics; cannot assess"
            elif not attacker_2xx:
                reason = "attacker denied"
            elif a.deny_match:
                reason = "attacker denied (deny heuristics)"
            elif allow_required and not a.allow_match:
                reason = "attacker denied (allow heuristics)"
            elif strict_body_match and (v.response_capped or a.response_capped):
                reason = "response capped; strict body match cannot assess"
            elif strict_body_match and not body_match:
                reason = "attacker 2xx but response body differs (strict mode)"
            elif body_match:
                reason = "attacker 2xx with matching response body"
            else:
                reason = "attacker 2xx (status-only signal)"

            total += 1
            if vulnerable:
                found_vulns += 1

            matrix_values_raw = ep.get("matrix_values")
            matrix_values = matrix_values_raw if isinstance(matrix_values_raw, dict) else None
            finding = Finding(
                endpoint=path,
                name=endpoint_name,
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
                victim_deny_match=bool(v.deny_match),
                attacker_deny_match=bool(a.deny_match),
                victim_allow_match=(bool(v.allow_match) if allow_required else None),
                attacker_allow_match=(bool(a.allow_match) if allow_required else None),
                victim_response_capped=bool(v.response_capped),
                attacker_response_capped=bool(a.response_capped),
                matrix_values=matrix_values,
            )
            out.write(json.dumps(finding.to_dict()) + "\n")

        if (only_name_set or only_path_set) and matched == 0:
            # Avoid silently writing an empty report when a filter doesn't match.
            parts: list[str] = []
            if only_name_set:
                parts.append(f"only-name={sorted(only_name_set)!r}")
            if only_path_set:
                parts.append(f"only-path={sorted(only_path_set)!r}")
            raise SystemExit("no endpoints matched filters: " + ", ".join(parts))
    finally:
        if out_handle is not None:
            out_handle.close()

    out_label = "stdout" if is_stdout else str(out_path)
    print(f"wrote {out_label} ({found_vulns}/{total} vulnerable)", file=sys.stderr)
    return 2 if (fail_on_vuln and found_vulns) else 0
