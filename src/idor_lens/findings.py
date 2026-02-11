from __future__ import annotations

import json
from typing import Any, Mapping


def confidence_rank(value: Any) -> int:
    if value == "high":
        return 2
    if value == "medium":
        return 1
    return 0


def min_rank(min_confidence: str) -> int:
    if min_confidence not in {"high", "medium", "none"}:
        raise SystemExit("--min-confidence must be one of: none, medium, high")
    return confidence_rank(min_confidence)


def key(item: Mapping[str, Any]) -> str:
    method = item.get("method")
    name = item.get("name")
    endpoint = item.get("endpoint")
    url = item.get("url")
    matrix_suffix = _matrix_suffix(item)

    if isinstance(method, str):
        m = method.upper()
    else:
        m = "GET"

    if isinstance(name, str) and name:
        return f"{m} {name}{matrix_suffix}"
    if isinstance(endpoint, str) and endpoint:
        return f"{m} {endpoint}{matrix_suffix}"
    if isinstance(url, str) and url:
        return f"{m} {url}{matrix_suffix}"
    return f"{m}{matrix_suffix}"


def _matrix_suffix(item: Mapping[str, Any]) -> str:
    raw = item.get("matrix_values")
    if not isinstance(raw, Mapping) or not raw:
        return ""

    parts: list[str] = []
    for key in sorted(raw):
        value = raw[key]
        try:
            rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except TypeError:
            rendered = str(value)
        parts.append(f"{key}={rendered}")
    if not parts:
        return ""
    return " [" + ", ".join(parts) + "]"


def is_vulnerable(item: Mapping[str, Any], *, min_rank: int) -> bool:
    vuln = item.get("vulnerable") is True
    if not vuln:
        return False
    return confidence_rank(item.get("confidence")) >= min_rank
