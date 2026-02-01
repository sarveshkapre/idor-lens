from __future__ import annotations

from pathlib import Path

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
