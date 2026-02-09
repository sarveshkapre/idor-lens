from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .findings import is_vulnerable, key as finding_key, min_rank
from .jsonl import open_text_out, read_jsonl


_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_RULE_ID = "IDOR.DifferentialAccess"


def write_sarif_report(in_path: Path, out_path: Path, *, min_confidence: str = "medium") -> None:
    items = [x for x in read_jsonl(in_path) if isinstance(x, dict)]
    min_conf = min_rank(min_confidence)

    results: list[dict[str, Any]] = []
    for item in items:
        if not is_vulnerable(item, min_rank=min_conf):
            continue

        conf = item.get("confidence")
        level = "error" if conf == "high" else "warning"

        url = item.get("url") if isinstance(item.get("url"), str) else ""
        method_val = item.get("method")
        method = method_val.upper() if isinstance(method_val, str) and method_val else "GET"
        victim_status = item.get("victim_status")
        attacker_status = item.get("attacker_status")
        reason = item.get("reason") if isinstance(item.get("reason"), str) else "vulnerable"

        status_bits: list[str] = []
        if isinstance(victim_status, int) and isinstance(attacker_status, int):
            status_bits.append(f"victim={victim_status}")
            status_bits.append(f"attacker={attacker_status}")
        status_str = f" ({', '.join(status_bits)})" if status_bits else ""

        fingerprint_src = finding_key(item)
        fp = hashlib.sha256(fingerprint_src.encode("utf-8", errors="replace")).hexdigest()

        sarif_result: dict[str, Any] = {
            "ruleId": _RULE_ID,
            "level": level,
            "message": {"text": f"{method} {url}{status_str}: {reason}"},
            "properties": {
                "idor_lens_key": fingerprint_src,
                "confidence": conf if isinstance(conf, str) else "",
                "reason": reason,
                "url": url,
                "method": method,
                "endpoint": item.get("endpoint") if isinstance(item.get("endpoint"), str) else "",
                "name": item.get("name") if isinstance(item.get("name"), str) else "",
                "victim_status": victim_status if isinstance(victim_status, int) else None,
                "attacker_status": attacker_status if isinstance(attacker_status, int) else None,
            },
            "fingerprints": {"idorLens/v1": fp},
        }
        if url:
            sarif_result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": url}}},
            ]

        results.append(sarif_result)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "idor-lens",
                        "rules": [
                            {
                                "id": _RULE_ID,
                                "name": "Insecure Direct Object Reference (IDOR)",
                                "shortDescription": {
                                    "text": "Potential IDOR via differential victim/attacker authorization"
                                },
                                "helpUri": "https://portswigger.net/web-security/access-control/idor",
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

    with open_text_out(out_path) as out:
        out.write(json.dumps(sarif, indent=2, sort_keys=True))
        out.write("\n")
