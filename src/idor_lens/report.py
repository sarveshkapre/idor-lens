from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from .jsonl import open_text_out, read_jsonl


@dataclass(frozen=True)
class ReportRow:
    endpoint: str
    name: str
    method: str
    url: str
    victim_status: int
    attacker_status: int
    vulnerable: bool
    confidence: str
    body_match: bool
    reason: str
    elapsed_ms: int
    victim_elapsed_ms: int | None
    attacker_elapsed_ms: int | None
    victim_attempts: int | None
    attacker_attempts: int | None
    victim_bytes: int | None
    attacker_bytes: int | None
    victim_sha256: str | None
    attacker_sha256: str | None
    victim_truncated: bool | None
    attacker_truncated: bool | None
    victim_error: str | None
    attacker_error: str | None
    victim_deny_match: bool | None
    attacker_deny_match: bool | None
    victim_allow_match: bool | None
    attacker_allow_match: bool | None
    victim_response_capped: bool | None
    attacker_response_capped: bool | None
    matrix_values: dict[str, Any] | None


def _as_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return default


def _as_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return default


def _as_str(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return default


def _to_report_row(d: dict[str, Any]) -> ReportRow:
    return ReportRow(
        endpoint=_as_str(d.get("endpoint"), default="/"),
        name=_as_str(d.get("name"), default=""),
        method=_as_str(d.get("method"), default="GET"),
        url=_as_str(d.get("url"), default=""),
        victim_status=_as_int(d.get("victim_status"), default=0),
        attacker_status=_as_int(d.get("attacker_status"), default=0),
        vulnerable=_as_bool(d.get("vulnerable"), default=False),
        confidence=_as_str(d.get("confidence"), default=""),
        body_match=_as_bool(d.get("body_match"), default=False),
        reason=_as_str(d.get("reason"), default=""),
        elapsed_ms=_as_int(d.get("elapsed_ms"), default=0),
        victim_elapsed_ms=d.get("victim_elapsed_ms")
        if isinstance(d.get("victim_elapsed_ms"), int)
        else None,
        attacker_elapsed_ms=d.get("attacker_elapsed_ms")
        if isinstance(d.get("attacker_elapsed_ms"), int)
        else None,
        victim_attempts=d.get("victim_attempts")
        if isinstance(d.get("victim_attempts"), int)
        else None,
        attacker_attempts=d.get("attacker_attempts")
        if isinstance(d.get("attacker_attempts"), int)
        else None,
        victim_bytes=d.get("victim_bytes") if isinstance(d.get("victim_bytes"), int) else None,
        attacker_bytes=d.get("attacker_bytes")
        if isinstance(d.get("attacker_bytes"), int)
        else None,
        victim_sha256=d.get("victim_sha256") if isinstance(d.get("victim_sha256"), str) else None,
        attacker_sha256=d.get("attacker_sha256")
        if isinstance(d.get("attacker_sha256"), str)
        else None,
        victim_truncated=d.get("victim_truncated")
        if isinstance(d.get("victim_truncated"), bool)
        else None,
        attacker_truncated=d.get("attacker_truncated")
        if isinstance(d.get("attacker_truncated"), bool)
        else None,
        victim_error=d.get("victim_error") if isinstance(d.get("victim_error"), str) else None,
        attacker_error=d.get("attacker_error")
        if isinstance(d.get("attacker_error"), str)
        else None,
        victim_deny_match=d.get("victim_deny_match")
        if isinstance(d.get("victim_deny_match"), bool)
        else None,
        attacker_deny_match=d.get("attacker_deny_match")
        if isinstance(d.get("attacker_deny_match"), bool)
        else None,
        victim_allow_match=d.get("victim_allow_match")
        if isinstance(d.get("victim_allow_match"), bool)
        else None,
        attacker_allow_match=d.get("attacker_allow_match")
        if isinstance(d.get("attacker_allow_match"), bool)
        else None,
        victim_response_capped=d.get("victim_response_capped")
        if isinstance(d.get("victim_response_capped"), bool)
        else None,
        attacker_response_capped=d.get("attacker_response_capped")
        if isinstance(d.get("attacker_response_capped"), bool)
        else None,
        matrix_values=d.get("matrix_values") if isinstance(d.get("matrix_values"), dict) else None,
    )


def write_html_report(in_path: Path, out_path: Path, *, title: str = "IDOR Lens Report") -> None:
    data = read_jsonl(in_path)
    rows = [_to_report_row(d) for d in data if isinstance(d, dict)]
    total = len(rows)
    vulns = sum(1 for r in rows if r.vulnerable)
    high = sum(1 for r in rows if r.vulnerable and r.confidence == "high")
    errors = sum(1 for r in rows if (r.victim_error or r.attacker_error))
    rendered_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%SZ")

    with open_text_out(out_path) as out:
        out.write(
            _render_html(
                rows,
                title=title,
                rendered_at=rendered_at,
                total=total,
                vulns=vulns,
                high=high,
                errors=errors,
            )
        )


def _render_html(
    rows: list[ReportRow],
    *,
    title: str,
    rendered_at: str,
    total: int,
    vulns: int,
    high: int,
    errors: int,
) -> str:
    safe_title = escape(title)

    row_html: list[str] = []
    for idx, r in enumerate(rows):
        vuln = "true" if r.vulnerable else "false"
        conf = escape(r.confidence or "")
        body_match = "true" if r.body_match else "false"

        details_bits: list[str] = []
        if r.victim_elapsed_ms is not None:
            details_bits.append(
                f"<div><span class='k'>Victim elapsed</span> {r.victim_elapsed_ms} ms</div>"
            )
        if r.attacker_elapsed_ms is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker elapsed</span> {r.attacker_elapsed_ms} ms</div>"
            )
        if r.victim_attempts is not None and r.victim_attempts > 1:
            details_bits.append(
                f"<div><span class='k'>Victim attempts</span> {r.victim_attempts}</div>"
            )
        if r.attacker_attempts is not None and r.attacker_attempts > 1:
            details_bits.append(
                f"<div><span class='k'>Attacker attempts</span> {r.attacker_attempts}</div>"
            )
        if r.victim_bytes is not None:
            details_bits.append(f"<div><span class='k'>Victim bytes</span> {r.victim_bytes}</div>")
        if r.attacker_bytes is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker bytes</span> {r.attacker_bytes}</div>"
            )
        if r.victim_sha256:
            details_bits.append(
                f"<div><span class='k'>Victim sha256</span> <code>{escape(r.victim_sha256)}</code></div>"
            )
        if r.attacker_sha256:
            details_bits.append(
                f"<div><span class='k'>Attacker sha256</span> <code>{escape(r.attacker_sha256)}</code></div>"
            )
        if r.victim_truncated is not None:
            details_bits.append(
                f"<div><span class='k'>Victim truncated</span> {str(r.victim_truncated).lower()}</div>"
            )
        if r.attacker_truncated is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker truncated</span> {str(r.attacker_truncated).lower()}</div>"
            )
        if r.victim_error:
            details_bits.append(
                f"<div><span class='k'>Victim error</span> <code>{escape(r.victim_error)}</code></div>"
            )
        if r.attacker_error:
            details_bits.append(
                f"<div><span class='k'>Attacker error</span> <code>{escape(r.attacker_error)}</code></div>"
            )
        if r.victim_deny_match is not None:
            details_bits.append(
                f"<div><span class='k'>Victim deny match</span> {str(r.victim_deny_match).lower()}</div>"
            )
        if r.attacker_deny_match is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker deny match</span> {str(r.attacker_deny_match).lower()}</div>"
            )
        if r.victim_allow_match is not None:
            details_bits.append(
                f"<div><span class='k'>Victim allow match</span> {str(r.victim_allow_match).lower()}</div>"
            )
        if r.attacker_allow_match is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker allow match</span> {str(r.attacker_allow_match).lower()}</div>"
            )
        if r.victim_response_capped is not None:
            details_bits.append(
                f"<div><span class='k'>Victim response capped</span> {str(r.victim_response_capped).lower()}</div>"
            )
        if r.attacker_response_capped is not None:
            details_bits.append(
                f"<div><span class='k'>Attacker response capped</span> {str(r.attacker_response_capped).lower()}</div>"
            )
        if r.matrix_values:
            details_bits.append(
                "<div><span class='k'>Matrix values</span> "
                f"<code>{escape(json.dumps(r.matrix_values, sort_keys=True, ensure_ascii=False))}</code></div>"
            )

        details_html = ""
        if details_bits:
            details_html = (
                "<details class='details'>"
                "<summary>Details</summary>"
                f"<div class='details-grid'>{''.join(details_bits)}</div>"
                "</details>"
            )

        # Data attributes for client-side filtering.
        matrix_search = (
            json.dumps(r.matrix_values, sort_keys=True, ensure_ascii=False)
            if r.matrix_values
            else ""
        )
        searchable = " ".join(
            [r.name, r.endpoint, r.method, r.url, r.reason, r.confidence, matrix_search]
        ).lower()
        row_html.append(
            "<tr "
            f"data-idx='{idx}' "
            f"data-vuln='{vuln}' "
            f"data-conf='{conf}' "
            f"data-search='{escape(searchable)}'"
            ">"
            f"<td class='mono'>{escape(r.method)}</td>"
            f"<td>{escape(r.name or '-')}</td>"
            f"<td class='mono'>{escape(r.endpoint)}</td>"
            f"<td class='mono'>{escape(r.url)}</td>"
            f"<td class='num'>{r.victim_status}</td>"
            f"<td class='num'>{r.attacker_status}</td>"
            f"<td class='pill {('bad' if r.vulnerable else 'ok')}'>{'VULN' if r.vulnerable else 'OK'}</td>"
            f"<td class='pill {('bad' if conf == 'high' else 'mid' if conf else 'ok')}'>{conf or '-'}</td>"
            f"<td class='mono'>{body_match}</td>"
            f"<td>{escape(r.reason)}</td>"
            f"<td class='num'>{r.elapsed_ms}</td>"
            f"<td>{details_html}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="color-scheme" content="light dark" />
    <title>{safe_title}</title>
    <style>
      :root {{
        --bg: #ffffff;
        --fg: #111827;
        --muted: #6b7280;
        --card: #f9fafb;
        --border: #e5e7eb;
        --bad: #b42318;
        --ok: #067647;
        --mid: #9a3412;
        --pill-bg: rgba(0,0,0,0.04);
        --shadow: 0 1px 2px rgba(0,0,0,0.06);
      }}
      @media (prefers-color-scheme: dark) {{
        :root {{
          --bg: #0b1020;
          --fg: #e5e7eb;
          --muted: #9ca3af;
          --card: #0f172a;
          --border: #23304a;
          --bad: #fb7185;
          --ok: #34d399;
          --mid: #fdba74;
          --pill-bg: rgba(255,255,255,0.06);
          --shadow: 0 1px 2px rgba(0,0,0,0.5);
        }}
      }}
      body {{
        margin: 0;
        background: var(--bg);
        color: var(--fg);
        font: 14px/1.4 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      }}
      .wrap {{
        max-width: 1200px;
        margin: 0 auto;
        padding: 24px;
      }}
      header {{
        display: grid;
        gap: 12px;
        align-items: start;
      }}
      h1 {{
        font-size: 20px;
        margin: 0;
        letter-spacing: -0.01em;
      }}
      .meta {{
        color: var(--muted);
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
      }}
      .cards {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
      }}
      @media (max-width: 900px) {{
        .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      }}
      @media (max-width: 520px) {{
        .cards {{ grid-template-columns: 1fr; }}
      }}
      .card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        box-shadow: var(--shadow);
      }}
      .card .k {{ color: var(--muted); font-size: 12px; }}
      .card .v {{ font-size: 18px; font-weight: 600; margin-top: 4px; }}
      .controls {{
        display: grid;
        grid-template-columns: 1fr auto auto;
        gap: 12px;
        margin-top: 12px;
      }}
      @media (max-width: 900px) {{
        .controls {{ grid-template-columns: 1fr; }}
      }}
      input[type="search"] {{
        width: 100%;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid var(--border);
        background: var(--card);
        color: var(--fg);
        outline: none;
      }}
      .check {{
        display: inline-flex;
        gap: 8px;
        align-items: center;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px 12px;
        user-select: none;
      }}
      table {{
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        margin-top: 16px;
        overflow: hidden;
        border-radius: 14px;
        border: 1px solid var(--border);
      }}
      thead th {{
        text-align: left;
        font-size: 12px;
        color: var(--muted);
        padding: 10px 12px;
        border-bottom: 1px solid var(--border);
        background: var(--card);
        position: sticky;
        top: 0;
        z-index: 1;
      }}
      tbody td {{
        padding: 10px 12px;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
      }}
      tbody tr:last-child td {{ border-bottom: none; }}
      .mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 12px;
      }}
      .num {{
        text-align: right;
        font-variant-numeric: tabular-nums;
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 4px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 700;
        background: var(--pill-bg);
        width: 64px;
      }}
      .pill.bad {{ color: var(--bad); }}
      .pill.ok {{ color: var(--ok); }}
      .pill.mid {{ color: var(--mid); }}
      .details {{
        margin-top: 4px;
      }}
      .details summary {{
        cursor: pointer;
        color: var(--muted);
        font-size: 12px;
      }}
      .details-grid {{
        margin-top: 8px;
        display: grid;
        gap: 6px;
      }}
      .details-grid .k {{
        color: var(--muted);
        margin-right: 8px;
      }}
      .hidden {{
        display: none;
      }}
      footer {{
        color: var(--muted);
        margin-top: 16px;
        font-size: 12px;
      }}
      code {{
        word-break: break-all;
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <header>
        <div>
          <h1>{safe_title}</h1>
          <div class="meta">
            <div>Rendered: <span class="mono">{escape(rendered_at)}</span></div>
            <div>Rows: <span class="mono" id="rows-total">{total}</span></div>
            <div>Visible: <span class="mono" id="rows-visible">{total}</span></div>
          </div>
        </div>

        <div class="cards" role="region" aria-label="Summary">
          <div class="card"><div class="k">Total</div><div class="v mono">{total}</div></div>
          <div class="card"><div class="k">Vulnerable</div><div class="v mono">{vulns}</div></div>
          <div class="card"><div class="k">High confidence</div><div class="v mono">{high}</div></div>
          <div class="card"><div class="k">Errors</div><div class="v mono">{errors}</div></div>
        </div>

        <div class="controls" role="region" aria-label="Filters">
          <input id="q" type="search" placeholder="Filter (endpoint, method, url, reason…)" aria-label="Filter rows" />
          <label class="check"><input id="onlyVuln" type="checkbox" /> Only vulnerable</label>
          <label class="check"><input id="onlyHigh" type="checkbox" /> Only high confidence</label>
        </div>
      </header>

      <table aria-label="IDOR Lens findings">
        <thead>
          <tr>
            <th>Method</th>
            <th>Name</th>
            <th>Endpoint</th>
            <th>URL</th>
            <th class="num">Victim</th>
            <th class="num">Attacker</th>
            <th>Vuln</th>
            <th>Confidence</th>
            <th>Body</th>
            <th>Reason</th>
            <th class="num">Elapsed</th>
            <th>More</th>
          </tr>
        </thead>
        <tbody id="tbody">
          {"".join(row_html)}
        </tbody>
      </table>

      <footer>
        Tip: use <span class="mono">--fail-on-vuln</span> for CI and <span class="mono">--strict-body-match</span> to reduce false positives.
      </footer>
    </div>

    <script>
      (function() {{
        var q = document.getElementById('q');
        var onlyVuln = document.getElementById('onlyVuln');
        var onlyHigh = document.getElementById('onlyHigh');
        var tbody = document.getElementById('tbody');
        var rowsVisible = document.getElementById('rows-visible');

        function apply() {{
          var needle = (q.value || '').trim().toLowerCase();
          var ov = !!onlyVuln.checked;
          var oh = !!onlyHigh.checked;
          var visible = 0;

          var trs = tbody.querySelectorAll('tr');
          for (var i = 0; i < trs.length; i++) {{
            var tr = trs[i];
            var ok = true;
            if (ov && tr.getAttribute('data-vuln') !== 'true') ok = false;
            if (oh && tr.getAttribute('data-conf') !== 'high') ok = false;
            if (needle) {{
              var hay = tr.getAttribute('data-search') || '';
              if (hay.indexOf(needle) === -1) ok = false;
            }}
            tr.classList.toggle('hidden', !ok);
            if (ok) visible++;
          }}
          rowsVisible.textContent = String(visible);
        }}

        q.addEventListener('input', apply);
        onlyVuln.addEventListener('change', apply);
        onlyHigh.addEventListener('change', apply);
        apply();
      }})();
    </script>
  </body>
</html>
"""
