from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
from _pytest.monkeypatch import MonkeyPatch

from idor_lens.runner import run_test


class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def test_run_writes_report(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> _Resp:
        return _Resp(200)

    monkeypatch.setattr(requests, "request", fake_request)

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
