from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, cast

import yaml

_ENV_PATTERN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*")


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def load_spec(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("spec must be a YAML mapping")
    expanded = expand_env(data)
    if not isinstance(expanded, dict):
        raise SystemExit("spec must be a YAML mapping")
    return cast(dict[str, Any], expanded)


def find_unexpanded_env_vars(value: Any) -> set[str]:
    found: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, str):
            for m in _ENV_PATTERN.findall(v):
                found.add(m)
            return
        if isinstance(v, list):
            for x in v:
                walk(x)
            return
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
            return

    walk(value)
    return found
