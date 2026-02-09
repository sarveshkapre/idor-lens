from __future__ import annotations

from pathlib import Path

import pytest

from idor_lens.validate import validate_spec


def test_validate_ok(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "json_ignore_paths:\n"
        "  - /updatedAt\n"
        "victim:\n  auth: Bearer x\n"
        "attacker:\n  auth: Bearer y\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_accepts_auth_file(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth_file: /tmp/victim-auth.txt\n"
        "attacker:\n  auth_file: /tmp/attacker-auth.txt\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_rejects_auth_and_auth_file_together(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n  auth: Bearer x\n  auth_file: /tmp/victim-auth.txt\n"
        "endpoints:\n  - path: /items/123\n    method: GET\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="victim must not set both auth and auth_file"):
        validate_spec(spec, require_env=True)


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


def test_validate_accepts_payload_modes_and_content_type(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      method: POST\n"
        "      body_mode: form\n"
        "      body:\n"
        "        csrf: abc\n"
        "attacker:\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      method: POST\n"
        "      body_mode: raw\n"
        "      content_type: application/json\n"
        "      body: '{\"seed\":true}'\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: POST\n"
        "    body_mode: raw\n"
        "    content_type: application/json\n"
        "    victim_body: '{\"id\":123}'\n"
        "    attacker_body_mode: form\n"
        "    attacker_body:\n"
        "      id: 999\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_accepts_deny_heuristics(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "deny_contains:\n"
        "  - access denied\n"
        "deny_regex:\n"
        "  - (?i)not authorized\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    deny_contains:\n"
        "      - forbidden\n",
        encoding="utf-8",
    )
    assert validate_spec(spec, require_env=True) == 0


def test_validate_rejects_invalid_deny_regex(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        'base_url: https://example.test\ndeny_regex:\n  - "["\nendpoints:\n  - path: /items/123\n',
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="deny_regex\\[1\\] is not a valid regex"):
        validate_spec(spec, require_env=True)


def test_validate_rejects_non_list_deny_contains(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "deny_contains: access denied\n"
        "endpoints:\n"
        "  - path: /items/123\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="deny_contains must be a list of strings"):
        validate_spec(spec, require_env=True)


def test_validate_rejects_invalid_json_ignore_path(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "json_ignore_paths:\n"
        "  - /items//updatedAt\n"
        "endpoints:\n"
        "  - path: /items/123\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="json_ignore_paths\\[1\\] is not a valid ignore path"):
        validate_spec(spec, require_env=True)


def test_validate_rejects_unknown_body_mode(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: POST\n"
        "    body_mode: xml\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="endpoints\\[1\\]\\.body_mode must be one of"):
        validate_spec(spec, require_env=True)


def test_validate_rejects_non_mapping_form_body(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "endpoints:\n"
        "  - path: /items/123\n"
        "    method: POST\n"
        "    body_mode: form\n"
        "    victim_body: not-a-map\n",
        encoding="utf-8",
    )
    with pytest.raises(
        SystemExit, match="endpoints\\[1\\]\\.victim_body must be a mapping when body_mode=form"
    ):
        validate_spec(spec, require_env=True)


def test_validate_rejects_non_string_raw_body(tmp_path: Path) -> None:
    spec = tmp_path / "spec.yml"
    spec.write_text(
        "base_url: https://example.test\n"
        "victim:\n"
        "  preflight:\n"
        "    - path: /bootstrap\n"
        "      body_mode: raw\n"
        "      body:\n"
        "        key: value\n"
        "endpoints:\n"
        "  - path: /items/123\n",
        encoding="utf-8",
    )
    with pytest.raises(
        SystemExit, match="victim\\.preflight\\[1\\]\\.body must be a string when body_mode=raw"
    ):
        validate_spec(spec, require_env=True)
