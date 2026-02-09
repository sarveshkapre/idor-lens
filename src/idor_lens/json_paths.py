from __future__ import annotations

import re
from typing import Any, Iterable

# Best-effort JSON field ignoring for strict body matching.
#
# Supported path formats:
# - JSON Pointer (RFC 6901): "/data/updatedAt", "/items/0/id"
# - Dot + brackets: "data.updatedAt", "items[0].id", "items[*].updatedAt"
# - Optional "$." prefix for dot paths: "$.data.updatedAt"
#
# Wildcards ("*") are supported in dot paths and (non-standard) in JSON pointer segments.

_WILDCARD = "*"


def parse_ignore_path(path: str) -> list[str | int]:
    raw = path.strip()
    if not raw:
        raise ValueError("path must be a non-empty string")

    if raw.startswith("/"):
        return _parse_json_pointer(raw)

    # "$.foo.bar" is a common convention.
    if raw == "$":
        raise ValueError("path '$' is not supported (would ignore the whole document)")
    if raw.startswith("$."):
        raw = raw[2:]

    return _parse_dot_path(raw)


def apply_ignore_paths(value: Any, paths: Iterable[str]) -> Any:
    # Mutates value in-place when it is a mapping/list.
    for p in paths:
        segs = parse_ignore_path(p)
        _delete_path(value, segs)
    return value


def _parse_json_pointer(ptr: str) -> list[str | int]:
    # RFC 6901: leading "/" then segments separated by "/".
    # We also allow "*" segments as a non-standard wildcard.
    out: list[str | int] = []
    for seg in ptr.split("/")[1:]:
        token = seg.replace("~1", "/").replace("~0", "~")
        if token == _WILDCARD:
            out.append(_WILDCARD)
            continue
        if token.isdigit():
            out.append(int(token))
            continue
        if not token:
            raise ValueError("empty JSON pointer segment is not allowed")
        out.append(token)
    if not out:
        raise ValueError("path '/' is not supported (would ignore the whole document)")
    return out


_DOT_NAME_RE = re.compile(r"^[^.\[\]]+$")


def _parse_dot_path(path: str) -> list[str | int]:
    out: list[str | int] = []
    s = path.strip()
    if not s:
        raise ValueError("path must be a non-empty string")

    i = 0
    n = len(s)
    while i < n:
        if s[i] == ".":
            i += 1
            continue

        if s[i] == "[":
            close = s.find("]", i + 1)
            if close == -1:
                raise ValueError("unclosed '[' in path")
            token = s[i + 1 : close].strip()
            if token == _WILDCARD:
                out.append(_WILDCARD)
            elif token.isdigit():
                out.append(int(token))
            else:
                raise ValueError(f"invalid bracket token: {token!r}")
            i = close + 1
            continue

        # Parse a name token up to '.' or '['.
        j = i
        while j < n and s[j] not in ".[":
            j += 1
        name = s[i:j].strip()
        if not name:
            raise ValueError("empty segment in path")
        if name == _WILDCARD:
            out.append(_WILDCARD)
        else:
            if not _DOT_NAME_RE.match(name):
                raise ValueError(f"invalid segment: {name!r}")
            out.append(name)
        i = j

    if not out:
        raise ValueError("path must include at least one segment")
    if out[-1] == _WILDCARD:
        raise ValueError("path cannot end with '*'")
    return out


def _delete_path(value: Any, segs: list[str | int]) -> None:
    if not segs:
        return

    head = segs[0]
    tail = segs[1:]

    if head == _WILDCARD:
        if isinstance(value, dict):
            for v in value.values():
                _delete_path(v, tail)
        elif isinstance(value, list):
            for v in value:
                _delete_path(v, tail)
        return

    if not tail:
        if isinstance(value, dict) and isinstance(head, str):
            value.pop(head, None)
            return
        if isinstance(value, list) and isinstance(head, int) and 0 <= head < len(value):
            # Avoid shifting indices; "ignored" list elements become null.
            value[head] = None
        return

    nxt: Any = None
    if isinstance(value, dict) and isinstance(head, str):
        nxt = value.get(head)
    elif isinstance(value, list) and isinstance(head, int) and 0 <= head < len(value):
        nxt = value[head]
    else:
        return

    _delete_path(nxt, tail)
