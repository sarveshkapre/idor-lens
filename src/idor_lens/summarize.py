from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .findings import is_vulnerable, key as finding_key, min_rank
from .jsonl import open_text_out, read_jsonl


@dataclass(frozen=True)
class Summary:
    total: int
    vulnerable: int
    high_confidence: int
    medium_confidence: int
    errors: int
    min_confidence: str
    vulnerable_keys: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "vulnerable": self.vulnerable,
            "high_confidence": self.high_confidence,
            "medium_confidence": self.medium_confidence,
            "errors": self.errors,
            "min_confidence": self.min_confidence,
            "vulnerable_keys": list(self.vulnerable_keys),
        }


def summarize_jsonl(in_path: Path, *, min_confidence: str = "medium") -> Summary:
    min_conf = min_rank(min_confidence)
    items = [x for x in read_jsonl(in_path) if isinstance(x, dict)]

    vulns: list[dict[str, Any]] = [d for d in items if is_vulnerable(d, min_rank=min_conf)]
    keys = sorted({finding_key(d) for d in vulns})

    high = sum(1 for d in vulns if d.get("confidence") == "high")
    medium = sum(1 for d in vulns if d.get("confidence") == "medium")
    errors = sum(1 for d in items if d.get("victim_error") or d.get("attacker_error"))

    return Summary(
        total=len(items),
        vulnerable=len(vulns),
        high_confidence=high,
        medium_confidence=medium,
        errors=errors,
        min_confidence=min_confidence,
        vulnerable_keys=keys,
    )


def write_summary(summary: Summary, out_path: Path, *, as_json: bool) -> None:
    with open_text_out(out_path) as out:
        if as_json:
            out.write(json.dumps(summary.to_dict()) + "\n")
            return

        out.write(
            f"total: {summary.total}, vulnerable: {summary.vulnerable} "
            f"(high={summary.high_confidence}, medium={summary.medium_confidence}), "
            f"errors: {summary.errors} (min_confidence={summary.min_confidence})\n"
        )
        if summary.vulnerable_keys:
            out.write("vulnerable endpoints:\n")
            for k in summary.vulnerable_keys:
                out.write(f"  - {k}\n")
