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


def read_jsonl_lines(lines: Iterable[str]) -> list[Any]:
    rows: list[Any] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        rows.append(json.loads(s))
    return rows


def read_jsonl(path: Path) -> list[Any]:
    with open_jsonl_in(path) as handle:
        return read_jsonl_lines(handle)
