from __future__ import annotations

import json
from pathlib import Path

from idor_lens.compare import compare_jsonl, write_compare_output


def test_compare_finds_new_vulns(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        "\n".join(
            [
                '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}',
                '{"endpoint":"/b","method":"GET","vulnerable":false,"confidence":"none"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    current = tmp_path / "current.jsonl"
    current.write_text(
        "\n".join(
            [
                '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}',
                '{"endpoint":"/b","method":"GET","vulnerable":true,"confidence":"medium"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    summary = compare_jsonl(baseline, current)
    assert summary.new_vulnerable == ["GET /b"]
    assert summary.resolved_vulnerable == []


def test_compare_respects_min_confidence(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        '{"endpoint":"/b","method":"GET","vulnerable":false,"confidence":"none"}\n',
        encoding="utf-8",
    )
    current = tmp_path / "current.jsonl"
    current.write_text(
        '{"endpoint":"/b","method":"GET","vulnerable":true,"confidence":"medium"}\n',
        encoding="utf-8",
    )

    summary = compare_jsonl(baseline, current, min_confidence="high")
    assert summary.new_vulnerable == []


def test_compare_can_write_json_output(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text("", encoding="utf-8")
    current = tmp_path / "current.jsonl"
    current.write_text(
        '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high"}\n', encoding="utf-8"
    )

    summary = compare_jsonl(baseline, current)
    out = tmp_path / "out.json"
    write_compare_output(summary, out, as_json=True)

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["new_vulnerable"] == ["GET /a"]
