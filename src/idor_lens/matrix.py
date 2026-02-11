from __future__ import annotations

import copy
import itertools
import re
from typing import Any

_MATRIX_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def expand_endpoints(endpoints: list[Any]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for idx, endpoint in enumerate(endpoints, start=1):
        if not isinstance(endpoint, dict):
            raise SystemExit("each endpoints[] entry must be a mapping")
        expanded.extend(expand_endpoint_matrix(endpoint, endpoint_index=idx))
    return expanded


def expand_endpoint_matrix(
    endpoint: dict[str, Any], *, endpoint_index: int
) -> list[dict[str, Any]]:
    matrix_raw = endpoint.get("matrix")
    if matrix_raw is None:
        return [dict(endpoint)]

    matrix = _parse_matrix(matrix_raw, endpoint_index=endpoint_index)
    endpoint_base = {k: v for k, v in endpoint.items() if k != "matrix"}

    if not matrix:
        return [dict(endpoint_base)]

    expanded: list[dict[str, Any]] = []
    matrix_keys = [name for name, _values in matrix]
    matrix_values = [values for _name, values in matrix]

    for combo in itertools.product(*matrix_values):
        context = {key: value for key, value in zip(matrix_keys, combo)}
        rendered = _substitute(
            copy.deepcopy(endpoint_base), context, location=f"endpoints[{endpoint_index}]"
        )
        rendered["matrix_values"] = copy.deepcopy(context)
        expanded.append(rendered)

    return expanded


def _parse_matrix(matrix: Any, *, endpoint_index: int) -> list[tuple[str, list[Any]]]:
    name = f"endpoints[{endpoint_index}].matrix"
    if not isinstance(matrix, dict):
        raise SystemExit(f"{name} must be a mapping of variable->non-empty list")

    parsed: list[tuple[str, list[Any]]] = []
    for raw_key, raw_values in matrix.items():
        if not isinstance(raw_key, str) or not _MATRIX_KEY_RE.fullmatch(raw_key):
            raise SystemExit(
                f"{name} keys must match ^[A-Za-z_][A-Za-z0-9_]*$ (invalid key: {raw_key!r})"
            )
        if not isinstance(raw_values, list) or not raw_values:
            raise SystemExit(f"{name}.{raw_key} must be a non-empty list")
        parsed.append((raw_key, list(raw_values)))
    return parsed


def _substitute(value: Any, context: dict[str, Any], *, location: str) -> Any:
    if isinstance(value, str):
        return _substitute_str(value, context, location=location)
    if isinstance(value, list):
        list_out: list[Any] = []
        for idx, item in enumerate(value, start=1):
            list_out.append(_substitute(item, context, location=f"{location}[{idx}]"))
        return list_out
    if isinstance(value, dict):
        dict_out: dict[Any, Any] = {}
        for key, item in value.items():
            # Preserve non-string keys as-is; endpoint validation handles schema typing.
            new_key = (
                _substitute_str(key, context, location=f"{location}.<key>")
                if isinstance(key, str)
                else key
            )
            child_key = str(new_key) if isinstance(new_key, str) and new_key else "<key>"
            dict_out[new_key] = _substitute(item, context, location=f"{location}.{child_key}")
        return dict_out
    return value


def _substitute_str(value: str, context: dict[str, Any], *, location: str) -> Any:
    matches = list(_PLACEHOLDER_RE.finditer(value))
    if not matches:
        return value

    unknown = sorted({m.group(1) for m in matches if m.group(1) not in context})
    if unknown:
        joined = ", ".join(unknown)
        raise SystemExit(f"{location} contains unknown matrix placeholders: {joined}")

    # Exact placeholder replacement keeps original type (for body/query numeric substitution).
    if len(matches) == 1 and matches[0].span() == (0, len(value)):
        return copy.deepcopy(context[matches[0].group(1)])

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        replacement = context[key]
        if isinstance(replacement, (dict, list)):
            raise SystemExit(
                f"{location} embeds matrix placeholder '{{{{{key}}}}}' inside a larger string; "
                "matrix value must be scalar"
            )
        if replacement is None:
            return ""
        return str(replacement)

    return _PLACEHOLDER_RE.sub(_replace, value)
