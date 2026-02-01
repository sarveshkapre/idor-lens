from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
from _pytest.monkeypatch import MonkeyPatch

from idor_lens.runner import run_test


class _Resp:
    def __init__(self, status_code: int, content: bytes = b"") -> None:
        self.status_code = status_code
        self.content = content


def test_run_writes_report(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        seen.append(kwargs)
        return _Resp(200, b'{"ok":true}')

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer victim\n"
        "attacker:\n  auth: Bearer attacker\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    data = json.loads(lines[0])
    assert data["vulnerable"] is True
    assert seen


def test_strict_body_match_requires_equal_bodies(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        auth = (kwargs.get("headers") or {}).get("Authorization")
        if auth == "Bearer victim":
            return _Resp(200, b'{"item":"victim"}')
        return _Resp(200, b'{"item":"attacker"}')

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer victim\n"
        "attacker:\n  auth: Bearer attacker\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0, strict_body_match=True)

    data = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
    assert data["vulnerable"] is False
    assert data["body_match"] is False


def test_preflight_and_cookies_are_supported(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        seen.append(kwargs)
        return _Resp(200, b"ok")

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  auth: Bearer victim\n"
        "  cookies:\n"
        "    session: v\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      method: GET\n"
        "attacker:\n"
        "  auth: Bearer attacker\n"
        "  cookies:\n"
        "    session: a\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      method: GET\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: GET\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    assert len(seen) >= 2
