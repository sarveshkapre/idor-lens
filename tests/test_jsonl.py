from __future__ import annotations

from pathlib import Path

import pytest

from idor_lens.jsonl import read_jsonl, read_jsonl_lines


def test_read_jsonl_lines_reports_line_number() -> None:
    with pytest.raises(SystemExit, match="line 2"):
        read_jsonl_lines(['{"ok":true}', '{"broken":'], source="sample.jsonl")


def test_read_jsonl_reports_file_path(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text('{"ok": true}\n{"broken":\n', encoding="utf-8")
    with pytest.raises(SystemExit, match=r"invalid JSONL in .*in\.jsonl at line 2"):
        read_jsonl(inp)
