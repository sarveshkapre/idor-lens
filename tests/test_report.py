from __future__ import annotations

from pathlib import Path

from idor_lens.report import write_html_report


def test_report_renders_html(tmp_path: Path) -> None:
    inp = tmp_path / "in.jsonl"
    inp.write_text(
        "\n".join(
            [
                '{"name":"scenario-a","endpoint":"/a","method":"GET","url":"https://x/a","victim_status":200,"attacker_status":200,"vulnerable":true,"confidence":"high","body_match":true,"reason":"ok","elapsed_ms":5}',
                '{"endpoint":"/b","method":"GET","url":"https://x/b","victim_status":200,"attacker_status":403,"vulnerable":false,"confidence":"none","body_match":false,"reason":"denied","elapsed_ms":7}',
                '{"name":"</script>","endpoint":"</script>","method":"GET","url":"https://x/c","victim_status":0,"attacker_status":0,"vulnerable":false,"confidence":"none","body_match":false,"reason":"<b>err</b>","elapsed_ms":1}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.html"
    write_html_report(inp, out, title="Test <Report>")

    html = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in html.lower()
    assert "Test &lt;Report&gt;" in html
    assert "&lt;/script&gt;" in html
    assert "&lt;b&gt;err&lt;/b&gt;" in html
    assert "<th>Name</th>" in html
    assert "Vulnerable" in html
