from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO


def open_jsonl_in(path: Path) -> TextIO:
    if str(path) == "-":
        return sys.stdin
    return path.open("r", encoding="utf-8")


def open_text_out(path: Path) -> TextIO:
    if str(path) == "-":
        return sys.stdout
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def read_jsonl_lines(lines: Iterable[str], *, source: str = "<input>") -> list[Any]:
    rows: list[Any] = []
    for line_num, line in enumerate(lines, start=1):
        s = line.strip()
        if not s:
            continue
        try:
            rows.append(json.loads(s))
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"invalid JSONL in {source} at line {line_num}: {exc.msg} (col {exc.colno})"
            ) from exc
    return rows


def read_jsonl(path: Path) -> list[Any]:
    with open_jsonl_in(path) as handle:
        source = "<stdin>" if str(path) == "-" else str(path)
        return read_jsonl_lines(handle, source=source)
