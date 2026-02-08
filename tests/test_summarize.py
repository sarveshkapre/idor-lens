from __future__ import annotations

import json
from pathlib import Path

from idor_lens.summarize import summarize_jsonl, write_summary


def test_summarize_counts(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        "\n".join(
            [
                '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}',
                '{"endpoint":"/b","method":"GET","vulnerable":true,"confidence":"medium"}',
                '{"endpoint":"/c","method":"GET","vulnerable":false,"confidence":"none"}',
                '{"endpoint":"/d","method":"GET","vulnerable":true,"confidence":"medium","victim_error":"x"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    s = summarize_jsonl(inp, min_confidence="medium")
    assert s.total == 4
    assert s.vulnerable == 3
    assert s.high_confidence == 1
    assert s.medium_confidence == 2
    assert s.errors == 1


def test_summarize_json_output(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}\n', encoding="utf-8"
    )
    s = summarize_jsonl(inp, min_confidence="high")
    out = tmp_path / "out.json"
    write_summary(s, out, as_json=True)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["vulnerable"] == 1
    assert data["vulnerable_keys"] == ["GET /a"]


def test_summarize_prefers_name_for_keys(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        '{"name":"scenario one","endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}\n',
        encoding="utf-8",
    )
    s = summarize_jsonl(inp, min_confidence="high")
    assert s.vulnerable_keys == ["GET scenario one"]
