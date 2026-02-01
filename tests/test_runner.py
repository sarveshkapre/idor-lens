from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
from _pytest.monkeypatch import MonkeyPatch
from pytest import CaptureFixture

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


def test_env_var_expansion_in_spec(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("VICTIM_TOKEN", "victim-token")
    monkeypatch.setenv("ATTACKER_TOKEN", "attacker-token")

    seen_auth: list[str | None] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        seen_auth.append((kwargs.get("headers") or {}).get("Authorization"))
        return _Resp(200, b"ok")

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer ${VICTIM_TOKEN}\n"
        "attacker:\n  auth: Bearer ${ATTACKER_TOKEN}\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    assert "Bearer victim-token" in seen_auth
    assert "Bearer attacker-token" in seen_auth


def test_stdout_output_is_jsonl_only(
    tmp_path: Path, monkeypatch: MonkeyPatch, capsys: CaptureFixture[str]
) -> None:
    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        auth = (kwargs.get("headers") or {}).get("Authorization")
        if auth == "Bearer victim":
            return _Resp(200, b'{"id":123,"owner":"victim"}')
        return _Resp(403, b"denied")

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer victim\n"
        "attacker:\n  auth: Bearer attacker\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )

    rc = run_test(spec, Path("-"), timeout=1.0)
    assert rc == 0

    captured = capsys.readouterr()
    assert "wrote" not in captured.out
    assert captured.out.count("\n") >= 1
    row = json.loads(captured.out.strip().splitlines()[0])
    assert row["endpoint"] == "/items/123"
    assert "wrote" in captured.err


def test_proxy_and_tls_flags_are_passed(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        seen.append(kwargs)
        return _Resp(200, b"ok")

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
    run_test(spec, out, timeout=1.0, verify_tls=False, proxy="http://127.0.0.1:8080")

    assert seen
    assert all(k.get("verify") is False for k in seen)
    assert all(
        k.get("proxies") == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        for k in seen
    )


def test_follow_redirects_flag_is_passed(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        seen.append(kwargs)
        return _Resp(200, b"ok")

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
    run_test(spec, out, timeout=1.0, follow_redirects=True)

    assert seen
    assert all(k.get("allow_redirects") is True for k in seen)


def test_retries_on_retryable_status(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    counts: dict[str, int] = {"victim": 0, "attacker": 0}

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        auth = (kwargs.get("headers") or {}).get("Authorization")
        key = "victim" if auth == "Bearer victim" else "attacker"
        counts[key] += 1
        if counts[key] == 1:
            return _Resp(503, b"try again")
        return _Resp(200, b"ok")

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
    run_test(spec, out, timeout=1.0, retries=1, retry_backoff_s=0.0)

    data = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
    assert data["victim_attempts"] == 2
    assert data["attacker_attempts"] == 2
    assert data["victim_status"] == 200
    assert data["attacker_status"] == 200


def test_retries_on_timeout(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    counts: dict[str, int] = {"victim": 0, "attacker": 0}

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        auth = (kwargs.get("headers") or {}).get("Authorization")
        key = "victim" if auth == "Bearer victim" else "attacker"
        counts[key] += 1
        if counts[key] == 1:
            raise requests.Timeout("timeout")
        return _Resp(200, b"ok")

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
    run_test(spec, out, timeout=1.0, retries=1, retry_backoff_s=0.0)

    data = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
    assert data["victim_attempts"] == 2
    assert data["attacker_attempts"] == 2
