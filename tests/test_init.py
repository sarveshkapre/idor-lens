from __future__ import annotations

from pathlib import Path

import pytest

from idor_lens.cli import main


def test_init_writes_spec_file(tmp_path: Path) -> None:
    out = tmp_path / "spec.yml"
    rc = main(["init", "--out", str(out), "--base-url", "https://example.test"])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert "base_url: https://example.test" in text
    assert "VICTIM_TOKEN" in text


def test_init_refuses_to_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "spec.yml"
    out.write_text("base_url: https://x\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["init", "--out", str(out), "--base-url", "https://example.test"])
