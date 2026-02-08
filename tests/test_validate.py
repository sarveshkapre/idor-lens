from __future__ import annotations

from pathlib import Path

import pytest

from idor_lens.validate import validate_spec


def test_validate_ok(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer x\n"
        "attacker:\n  auth: Bearer y\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_require_env_fails_on_unexpanded(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer ${VICTIM_TOKEN}\n"
        "attacker:\n  auth: Bearer ${ATTACKER_TOKEN}\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 2


def test_validate_accepts_endpoint_name_and_cookie_overrides(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  auth: Bearer x\n"
        "  cookies:\n"
        "    session: victim\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      method: GET\n"
        "attacker:\n"
        "  auth: Bearer y\n"
        "endpoints:\n"
        "  - name: item read scenario\n"
        "    path: /items/123\n"
        "    method: GET\n"
        "    cookies:\n"
        "      locale: en-US\n"
        "    victim_cookies:\n"
        "      session: victim-endpoint\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_rejects_invalid_retry_type(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "retries: true\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="retries must be an integer"):
        validate_spec(spec, require_env=True)


def test_validate_rejects_empty_endpoint_cookie_keys(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: GET\n"
        "    cookies:\n"
        '      "": bad\n',
        encoding="utf-8",
    )
    with pytest.raises(
        SystemExit, match="endpoints\\[1\\]\\.cookies keys must be non-empty strings"
    ):
        validate_spec(spec, require_env=True)
