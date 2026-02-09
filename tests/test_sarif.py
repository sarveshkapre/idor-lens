from __future__ import annotations

import json
from pathlib import Path

from idor_lens.sarif import write_sarif_report


def test_sarif_writes_results_for_vulnerabilities(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        "\n".join(
            [
                '{"endpoint":"/a","method":"GET","url":"https://example.test/a","vulnerable":true,"confidence":"high","reason":"x","victim_status":200,"attacker_status":200}',
                '{"endpoint":"/b","method":"GET","url":"https://example.test/b","vulnerable":true,"confidence":"medium","reason":"y","victim_status":200,"attacker_status":200}',
                '{"endpoint":"/c","method":"GET","url":"https://example.test/c","vulnerable":false,"confidence":"none"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "out.sarif"
    write_sarif_report(inp, out, min_confidence="medium")

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "runs" in data and isinstance(data["runs"], list)
    run0 = data["runs"][0]
    assert run0["tool"]["driver"]["name"] == "idor-lens"
    assert isinstance(run0.get("results"), list)
    # Only the two vulnerable items should be emitted.
    assert len(run0["results"]) == 2
    assert all(r["ruleId"] == "IDOR.DifferentialAccess" for r in run0["results"])
    assert any(r.get("level") == "error" for r in run0["results"])
    assert any(r.get("level") == "warning" for r in run0["results"])


def test_sarif_respects_min_confidence(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        '{"endpoint":"/b","method":"GET","url":"https://example.test/b","vulnerable":true,"confidence":"medium"}\n',
        encoding="utf-8",
    )
    out = tmp_path / "out.sarif"
    write_sarif_report(inp, out, min_confidence="high")

    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["runs"][0]["results"]) == 0
