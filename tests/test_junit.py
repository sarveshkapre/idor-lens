from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from idor_lens.junit import write_junit_report


def test_junit_writes_failures_and_errors(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        "\n".join(
            [
                '{"endpoint":"/a","method":"GET","vulnerable":true,"confidence":"high","reason":"x","elapsed_ms":10}',
                '{"endpoint":"/b","method":"GET","vulnerable":true,"confidence":"medium","reason":"y","elapsed_ms":20}',
                '{"endpoint":"/c","method":"GET","vulnerable":false,"confidence":"none","elapsed_ms":30}',
                '{"endpoint":"/d","method":"GET","vulnerable":true,"confidence":"high","attacker_error":"boom"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    out = tmp_path / "out.xml"
    write_junit_report(inp, out, min_confidence="medium")

    root = ET.fromstring(out.read_text(encoding="utf-8"))
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "2"
    assert root.attrib["errors"] == "1"

    cases = list(root.findall("testcase"))
    assert len(cases) == 4
    assert any(c.attrib.get("name") == "GET /a" for c in cases)

    by_name = {c.attrib.get("name"): c for c in cases}
    assert by_name["GET /a"].find("failure") is not None
    assert by_name["GET /b"].find("failure") is not None
    assert by_name["GET /c"].find("failure") is None
    assert by_name["GET /d"].find("error") is not None


def test_junit_respects_min_confidence(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        '{"endpoint":"/b","method":"GET","vulnerable":true,"confidence":"medium"}\n',
        encoding="utf-8",
    )

    out = tmp_path / "out.xml"
    write_junit_report(inp, out, min_confidence="high")

    root = ET.fromstring(out.read_text(encoding="utf-8"))
    assert root.attrib["failures"] == "0"
