from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .findings import is_vulnerable, key as finding_key, min_rank
from .jsonl import open_text_out, read_jsonl


def write_junit_report(in_path: Path, out_path: Path, *, min_confidence: str = "medium") -> None:
    items = [x for x in read_jsonl(in_path) if isinstance(x, dict)]
    min_conf = min_rank(min_confidence)

    failures = 0
    errors = 0
    total_time_s = 0.0

    suite = ET.Element(
        "testsuite",
        attrib={
            "name": "idor-lens",
            "tests": str(len(items)),
            "failures": "0",
            "errors": "0",
            "time": "0",
        },
    )

    for item in items:
        tc_name = finding_key(item)
        elapsed_ms = item.get("elapsed_ms")
        time_s = (
            float(elapsed_ms) / 1000.0 if isinstance(elapsed_ms, int) and elapsed_ms >= 0 else 0.0
        )
        total_time_s += time_s

        tc = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "classname": "idor-lens",
                "name": tc_name,
                "time": f"{time_s:.3f}",
            },
        )

        victim_error = item.get("victim_error")
        attacker_error = item.get("attacker_error")
        if isinstance(victim_error, str) and victim_error:
            errors += 1
            node = ET.SubElement(tc, "error", attrib={"message": "victim request error"})
            node.text = victim_error
            continue
        if isinstance(attacker_error, str) and attacker_error:
            errors += 1
            node = ET.SubElement(tc, "error", attrib={"message": "attacker request error"})
            node.text = attacker_error
            continue

        if is_vulnerable(item, min_rank=min_conf):
            failures += 1
            reason = item.get("reason")
            message = reason if isinstance(reason, str) else "vulnerable"
            node = ET.SubElement(tc, "failure", attrib={"message": message})
            node.text = _failure_text(item)

    suite.set("failures", str(failures))
    suite.set("errors", str(errors))
    suite.set("time", f"{total_time_s:.3f}")

    xml_bytes = ET.tostring(suite, encoding="utf-8", xml_declaration=True)
    with open_text_out(out_path) as out:
        out.write(xml_bytes.decode("utf-8"))
        out.write("\n")


def _failure_text(item: dict[str, Any]) -> str:
    bits: list[str] = []
    url = item.get("url")
    if isinstance(url, str) and url:
        bits.append(f"url: {url}")
    victim_status = item.get("victim_status")
    attacker_status = item.get("attacker_status")
    if isinstance(victim_status, int) and isinstance(attacker_status, int):
        bits.append(f"victim_status: {victim_status}, attacker_status: {attacker_status}")
    conf = item.get("confidence")
    if isinstance(conf, str) and conf:
        bits.append(f"confidence: {conf}")
    reason = item.get("reason")
    if isinstance(reason, str) and reason:
        bits.append(f"reason: {reason}")
    return "\n".join(bits) if bits else "vulnerable"
