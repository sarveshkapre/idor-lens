from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Mapping

from .spec import find_unexpanded_env_vars, load_spec

_BODY_MODE_JSON = "json"
_BODY_MODE_FORM = "form"
_BODY_MODE_RAW = "raw"
_BODY_MODES = {_BODY_MODE_JSON, _BODY_MODE_FORM, _BODY_MODE_RAW}


def _as_mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{name} must be a mapping")
    return value


def _require_non_empty_str(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{name} must be a non-empty string")
    return value


def _require_optional_non_empty_str(value: Any, *, name: str) -> None:
    if value is None:
        return
    _require_non_empty_str(value, name=name)


def _require_bool(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, bool):
        raise SystemExit(f"{name} must be a boolean")


def _require_non_negative_int(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool):
        raise SystemExit(f"{name} must be an integer")
    if value < 0:
        raise SystemExit(f"{name} must be >= 0")


def _require_number(value: Any, *, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise SystemExit(f"{name} must be a number")
    return float(value)


def _require_positive_number(value: Any, *, name: str) -> None:
    if value is None:
        return
    if _require_number(value, name=name) <= 0:
        raise SystemExit(f"{name} must be > 0")


def _require_non_negative_number(value: Any, *, name: str) -> None:
    if value is None:
        return
    if _require_number(value, name=name) < 0:
        raise SystemExit(f"{name} must be >= 0")


def _require_string_map(value: Any, *, name: str, non_empty_keys: bool = False) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise SystemExit(f"{name} must be a mapping of string->string")
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SystemExit(f"{name} must be a mapping of string->string")
        if non_empty_keys and not k:
            raise SystemExit(f"{name} keys must be non-empty strings")


def _require_int_list(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SystemExit(f"{name} must be a list of integers")
    for item in value:
        if not isinstance(item, int) or isinstance(item, bool):
            raise SystemExit(f"{name} must be a list of integers")


def _require_string_list(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SystemExit(f"{name} must be a list of strings")
    for item in value:
        if not isinstance(item, str) or not item:
            raise SystemExit(f"{name} must be a list of non-empty strings")


def _require_regex_list(value: Any, *, name: str) -> None:
    if value is None:
        return
    _require_string_list(value, name=name)
    assert isinstance(value, list)
    for idx, pat in enumerate(value, start=1):
        try:
            re.compile(pat)
        except re.error as exc:
            raise SystemExit(f"{name}[{idx}] is not a valid regex: {exc}") from exc


def _require_body_mode(value: Any, *, name: str, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{name} must be one of: json, form, raw")
    normalized = value.lower()
    if normalized not in _BODY_MODES:
        raise SystemExit(f"{name} must be one of: json, form, raw")
    return normalized


def _require_body_for_mode(value: Any, *, body_mode: str, name: str) -> None:
    if body_mode == _BODY_MODE_JSON:
        return
    if body_mode == _BODY_MODE_FORM:
        if value is None:
            return
        if not isinstance(value, dict):
            raise SystemExit(f"{name} must be a mapping when body_mode=form")
        for key in value:
            if not isinstance(key, str):
                raise SystemExit(f"{name} must be a mapping with string keys when body_mode=form")
        return
    if value is not None and not isinstance(value, str):
        raise SystemExit(f"{name} must be a string when body_mode=raw")


def _validate_preflight(value: Any, *, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SystemExit(f"{name}.preflight must be a list")
    for idx, step in enumerate(value, start=1):
        step_name = f"{name}.preflight[{idx}]"
        step_map = _as_mapping(step, name=step_name)
        _require_non_empty_str(step_map.get("path"), name=f"{step_name}.path")
        method = step_map.get("method")
        if method is not None:
            _require_non_empty_str(method, name=f"{step_name}.method")
        timeout = step_map.get("timeout")
        if timeout is not None:
            _require_positive_number(timeout, name=f"{step_name}.timeout")
        _require_string_map(step_map.get("headers"), name=f"{step_name}.headers")
        _require_optional_non_empty_str(
            step_map.get("content_type"), name=f"{step_name}.content_type"
        )

        body_mode = _require_body_mode(
            step_map.get("body_mode"),
            name=f"{step_name}.body_mode",
            default=_BODY_MODE_JSON,
        )
        _require_body_for_mode(step_map.get("body"), body_mode=body_mode, name=f"{step_name}.body")


def _validate_role(value: Any, *, name: str) -> Mapping[str, Any]:
    role = _as_mapping(value, name=name)
    _require_optional_non_empty_str(role.get("auth"), name=f"{name}.auth")
    _require_string_map(role.get("headers"), name=f"{name}.headers")
    _require_string_map(role.get("cookies"), name=f"{name}.cookies", non_empty_keys=True)
    _validate_preflight(role.get("preflight"), name=name)
    _require_positive_number(role.get("timeout"), name=f"{name}.timeout")
    _require_bool(role.get("verify_tls"), name=f"{name}.verify_tls")
    _require_bool(role.get("follow_redirects"), name=f"{name}.follow_redirects")
    _require_non_negative_int(role.get("retries"), name=f"{name}.retries")
    _require_non_negative_number(role.get("retry_backoff_s"), name=f"{name}.retry_backoff_s")
    _require_optional_non_empty_str(role.get("proxy"), name=f"{name}.proxy")
    return role


def _validate_endpoint(value: Any, *, idx: int) -> None:
    name = f"endpoints[{idx}]"
    endpoint = _as_mapping(value, name=name)
    _require_non_empty_str(endpoint.get("path"), name=f"{name}.path")
    method = endpoint.get("method")
    if method is not None:
        _require_non_empty_str(method, name=f"{name}.method")
    display_name = endpoint.get("name")
    if display_name is not None:
        _require_non_empty_str(display_name, name=f"{name}.name")
    _require_string_map(endpoint.get("headers"), name=f"{name}.headers")
    _require_string_map(endpoint.get("victim_headers"), name=f"{name}.victim_headers")
    _require_string_map(endpoint.get("attacker_headers"), name=f"{name}.attacker_headers")
    _require_string_map(endpoint.get("cookies"), name=f"{name}.cookies", non_empty_keys=True)
    _require_string_map(
        endpoint.get("victim_cookies"), name=f"{name}.victim_cookies", non_empty_keys=True
    )
    _require_string_map(
        endpoint.get("attacker_cookies"), name=f"{name}.attacker_cookies", non_empty_keys=True
    )
    _require_positive_number(endpoint.get("timeout"), name=f"{name}.timeout")
    _require_positive_number(endpoint.get("victim_timeout"), name=f"{name}.victim_timeout")
    _require_positive_number(endpoint.get("attacker_timeout"), name=f"{name}.attacker_timeout")
    _require_bool(endpoint.get("follow_redirects"), name=f"{name}.follow_redirects")
    _require_bool(endpoint.get("victim_follow_redirects"), name=f"{name}.victim_follow_redirects")
    _require_bool(
        endpoint.get("attacker_follow_redirects"), name=f"{name}.attacker_follow_redirects"
    )
    _require_optional_non_empty_str(endpoint.get("content_type"), name=f"{name}.content_type")
    _require_optional_non_empty_str(
        endpoint.get("victim_content_type"), name=f"{name}.victim_content_type"
    )
    _require_optional_non_empty_str(
        endpoint.get("attacker_content_type"), name=f"{name}.attacker_content_type"
    )
    _require_string_list(endpoint.get("deny_contains"), name=f"{name}.deny_contains")
    _require_regex_list(endpoint.get("deny_regex"), name=f"{name}.deny_regex")

    endpoint_body = endpoint.get("victim_body")
    attacker_body = endpoint.get("attacker_body", endpoint_body)
    endpoint_body_mode = _require_body_mode(
        endpoint.get("body_mode"), name=f"{name}.body_mode", default=_BODY_MODE_JSON
    )
    victim_body_mode = _require_body_mode(
        endpoint.get("victim_body_mode"),
        name=f"{name}.victim_body_mode",
        default=endpoint_body_mode,
    )
    attacker_body_mode = _require_body_mode(
        endpoint.get("attacker_body_mode"),
        name=f"{name}.attacker_body_mode",
        default=victim_body_mode,
    )
    _require_body_for_mode(endpoint_body, body_mode=victim_body_mode, name=f"{name}.victim_body")
    _require_body_for_mode(
        attacker_body, body_mode=attacker_body_mode, name=f"{name}.attacker_body"
    )


def validate_spec(spec_path: Path, *, require_env: bool) -> int:
    spec = load_spec(spec_path)

    base_url = spec.get("base_url")
    if base_url is None or base_url == "":
        raise SystemExit("missing base_url in spec")
    if not isinstance(base_url, str):
        raise SystemExit("base_url must be a string")

    _require_bool(spec.get("verify_tls"), name="verify_tls")
    _require_optional_non_empty_str(spec.get("proxy"), name="proxy")
    _require_bool(spec.get("follow_redirects"), name="follow_redirects")
    _require_non_negative_int(spec.get("retries"), name="retries")
    _require_non_negative_number(spec.get("retry_backoff_s"), name="retry_backoff_s")
    _require_int_list(spec.get("retry_statuses"), name="retry_statuses")
    _require_string_list(spec.get("deny_contains"), name="deny_contains")
    _require_regex_list(spec.get("deny_regex"), name="deny_regex")

    _validate_role(spec.get("victim", {}), name="victim")
    _validate_role(spec.get("attacker", {}), name="attacker")

    endpoints = spec.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise SystemExit("spec must include endpoints list")
    for idx, ep in enumerate(endpoints, start=1):
        _validate_endpoint(ep, idx=idx)

    missing = find_unexpanded_env_vars(spec)
    if missing:
        msg = "unexpanded env vars found: " + ", ".join(sorted(missing))
        if require_env:
            print(msg, file=sys.stderr)
            return 2
        print("warning: " + msg, file=sys.stderr)

    return 0
