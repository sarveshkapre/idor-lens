from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests
import pytest
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


def test_timeout_overrides_are_applied(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    seen_timeouts: dict[str, float] = {}

    def fake_request(*_args: Any, **kwargs: Any) -> _Resp:
        auth = (kwargs.get("headers") or {}).get("Authorization")
        key = "victim" if auth == "Bearer victim" else "attacker"
        timeout_val = kwargs.get("timeout")
        if not isinstance(timeout_val, (int, float)):
            raise AssertionError("timeout not passed as number")
        seen_timeouts[key] = float(timeout_val)
        return _Resp(200, b"ok")

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  auth: Bearer victim\n"
        "  timeout: 0.5\n"
        "attacker:\n"
        "  auth: Bearer attacker\n"
        "  timeout: 0.6\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: GET\n"
        "    timeout: 1.2\n"
        "    victim_timeout: 1.5\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=10.0)

    assert seen_timeouts["victim"] == 1.5
    assert seen_timeouts["attacker"] == 1.2


def test_endpoint_name_and_cookie_overrides_are_applied(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
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
        "    session: victim-default\n"
        "attacker:\n"
        "  auth: Bearer attacker\n"
        "  cookies:\n"
        "    session: attacker-default\n"
        "endpoints:\n"
        "  - name: item read regression\n"
        "    path: /items/123\n"
        "    method: GET\n"
        "    cookies:\n"
        "      locale: en-US\n"
        "    victim_cookies:\n"
        "      session: victim-endpoint\n"
        "    attacker_cookies:\n"
        "      session: attacker-endpoint\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    assert len(seen) == 2
    victim_call = next(
        k for k in seen if (k.get("headers") or {}).get("Authorization") == "Bearer victim"
    )
    attacker_call = next(
        k for k in seen if (k.get("headers") or {}).get("Authorization") == "Bearer attacker"
    )
    assert victim_call["cookies"] == {"locale": "en-US", "session": "victim-endpoint"}
    assert attacker_call["cookies"] == {"locale": "en-US", "session": "attacker-endpoint"}

    data = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
    assert data["name"] == "item read regression"


def test_endpoint_form_body_mode_sends_data_with_content_type(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
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
        "endpoints:\n"
        "  - path: /forms/submit\n"
        "    method: POST\n"
        "    body_mode: form\n"
        "    content_type: application/x-www-form-urlencoded\n"
        "    victim_body:\n"
        "      id: 123\n"
        "    attacker_body:\n"
        "      id: 999\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    assert len(seen) == 2
    for call in seen:
        assert call["json"] is None
        assert call["data"] in ({"id": 123}, {"id": 999})
        assert call["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_endpoint_raw_body_mode_defaults_to_text_plain(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
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
        "endpoints:\n"
        "  - path: /raw\n"
        "    method: POST\n"
        "    body_mode: raw\n"
        "    victim_body: '{\"id\":123}'\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    assert len(seen) == 2
    for call in seen:
        assert call["json"] is None
        assert call["data"] == '{"id":123}'
        assert call["headers"]["Content-Type"] == "text/plain; charset=utf-8"


def test_preflight_body_mode_supports_form_and_raw(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    seen: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_request(*args: Any, **kwargs: Any) -> _Resp:
        seen.append((args, kwargs))
        return _Resp(200, b"ok")

    monkeypatch.setattr(requests.sessions.Session, "request", fake_request)

    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  auth: Bearer victim\n"
        "  preflight:\n"
        "    - path: /victim/bootstrap\n"
        "      method: POST\n"
        "      body_mode: form\n"
        "      body:\n"
        "        csrf: victim\n"
        "attacker:\n"
        "  auth: Bearer attacker\n"
        "  preflight:\n"
        "    - path: /attacker/bootstrap\n"
        "      method: POST\n"
        "      body_mode: raw\n"
        "      content_type: application/xml\n"
        "      body: '<bootstrap role=\"attacker\"/>'\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: GET\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    run_test(spec, out, timeout=1.0)

    victim_preflight = next(
        args_kwargs for args_kwargs in seen if args_kwargs[0][2].endswith("/victim/bootstrap")
    )
    attacker_preflight = next(
        args_kwargs for args_kwargs in seen if args_kwargs[0][2].endswith("/attacker/bootstrap")
    )
    assert victim_preflight[1]["data"] == {"csrf": "victim"}
    assert victim_preflight[1]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert attacker_preflight[1]["data"] == '<bootstrap role="attacker"/>'
    assert attacker_preflight[1]["headers"]["Content-Type"] == "application/xml"


def test_raw_body_mode_rejects_non_string_body(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: POST\n"
        "    body_mode: raw\n"
        "    victim_body:\n"
        "      id: 123\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.jsonl"
    with pytest.raises(SystemExit, match="endpoints\\[1\\]\\.victim\\.body must be a string"):
        run_test(spec, out, timeout=1.0)
