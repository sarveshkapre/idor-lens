from __future__ import annotations

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

    if isinstance(method, str):
        m = method.upper()
    else:
        m = "GET"

    if isinstance(name, str) and name:
        return f"{m} {name}"
    if isinstance(endpoint, str) and endpoint:
        return f"{m} {endpoint}"
    if isinstance(url, str) and url:
        return f"{m} {url}"
    return m


def is_vulnerable(item: Mapping[str, Any], *, min_rank: int) -> bool:
    vuln = item.get("vulnerable") is True
    if not vuln:
        return False
    return confidence_rank(item.get("confidence")) >= min_rank
