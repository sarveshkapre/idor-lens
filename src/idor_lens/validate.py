from __future__ import annotations

import sys
from pathlib import Path

from .spec import find_unexpanded_env_vars, load_spec


def validate_spec(spec_path: Path, *, require_env: bool) -> int:
    spec = load_spec(spec_path)

    base_url = spec.get("base_url")
    if not isinstance(base_url, str) or not base_url:
        raise SystemExit("missing base_url in spec")

    endpoints = spec.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise SystemExit("spec must include endpoints list")
    for idx, ep in enumerate(endpoints, start=1):
        if not isinstance(ep, dict):
            raise SystemExit(f"endpoints[{idx}] must be a mapping")
        path = ep.get("path")
        if not isinstance(path, str) or not path:
            raise SystemExit(f"endpoints[{idx}].path must be a non-empty string")
        method = ep.get("method")
        if method is not None and (not isinstance(method, str) or not method):
            raise SystemExit(f"endpoints[{idx}].method must be a non-empty string")

    missing = find_unexpanded_env_vars(spec)
    if missing:
        msg = "unexpanded env vars found: " + ", ".join(sorted(missing))
        if require_env:
            print(msg, file=sys.stderr)
            return 2
        print("warning: " + msg, file=sys.stderr)

    return 0
