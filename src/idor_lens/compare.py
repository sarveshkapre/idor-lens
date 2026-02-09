from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .findings import is_vulnerable, key as finding_key, min_rank
from .jsonl import open_text_out, read_jsonl


@dataclass(frozen=True)
class CompareSummary:
    total_baseline: int
    total_current: int
    vulnerable_baseline: int
    vulnerable_current: int
    new_vulnerable: list[str]
    resolved_vulnerable: list[str]
    min_confidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_baseline": self.total_baseline,
            "total_current": self.total_current,
            "vulnerable_baseline": self.vulnerable_baseline,
            "vulnerable_current": self.vulnerable_current,
            "new_vulnerable": list(self.new_vulnerable),
            "resolved_vulnerable": list(self.resolved_vulnerable),
            "min_confidence": self.min_confidence,
        }


def compare_jsonl(
    baseline_path: Path,
    current_path: Path,
    *,
    min_confidence: str = "medium",
) -> CompareSummary:
    min_conf = min_rank(min_confidence)

    baseline_items = [x for x in read_jsonl(baseline_path) if isinstance(x, dict)]
    current_items = [x for x in read_jsonl(current_path) if isinstance(x, dict)]

    baseline_vuln_keys = {
        finding_key(d) for d in baseline_items if is_vulnerable(d, min_rank=min_conf)
    }
    current_vuln_keys = {
        finding_key(d) for d in current_items if is_vulnerable(d, min_rank=min_conf)
    }

    new = sorted(current_vuln_keys - baseline_vuln_keys)
    resolved = sorted(baseline_vuln_keys - current_vuln_keys)

    return CompareSummary(
        total_baseline=len(baseline_items),
        total_current=len(current_items),
        vulnerable_baseline=len(baseline_vuln_keys),
        vulnerable_current=len(current_vuln_keys),
        new_vulnerable=new,
        resolved_vulnerable=resolved,
        min_confidence=min_confidence,
    )


def write_compare_output(summary: CompareSummary, out_path: Path, *, as_json: bool) -> None:
    with open_text_out(out_path) as out:
        if as_json:
            out.write(json.dumps(summary.to_dict()) + "\n")
            return

        out.write(
            f"baseline: {summary.vulnerable_baseline} vulnerable (of {summary.total_baseline}), "
            f"current: {summary.vulnerable_current} vulnerable (of {summary.total_current}), "
            f"new: {len(summary.new_vulnerable)}, resolved: {len(summary.resolved_vulnerable)} "
            f"(min_confidence={summary.min_confidence})\n"
        )
        if summary.new_vulnerable:
            out.write("new vulnerabilities:\n")
            for k in summary.new_vulnerable:
                out.write(f"  - {k}\n")
        if summary.resolved_vulnerable:
            out.write("resolved vulnerabilities:\n")
            for k in summary.resolved_vulnerable:
                out.write(f"  - {k}\n")
