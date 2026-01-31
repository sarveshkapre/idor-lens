from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml


@dataclass(frozen=True)
class Finding:
    endpoint: str
    method: str
    victim_status: int
    attacker_status: int
    vulnerable: bool
    reason: str
    elapsed_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "vulnerable": self.vulnerable,
            "reason": self.reason,
            "elapsed_ms": self.elapsed_ms,
        }


def _load_spec(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("spec must be a YAML mapping")
    return data


def _headers(token: str | None, extra: dict[str, str]) -> dict[str, str]:
    headers = dict(extra)
    if token:
        headers["Authorization"] = token
    return headers


def run_test(spec_path: Path, out_path: Path, timeout: float) -> int:
    spec = _load_spec(spec_path)
    base_url = spec.get("base_url")
    if not base_url:
        raise SystemExit("missing base_url in spec")

    victim = spec.get("victim", {})
    attacker = spec.get("attacker", {})
    endpoints = spec.get("endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        raise SystemExit("spec must include endpoints list")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            path = ep.get("path", "/")
            method = ep.get("method", "GET").upper()
            victim_token = victim.get("auth")
            attacker_token = attacker.get("auth")
            victim_headers = _headers(victim_token, victim.get("headers", {}))
            attacker_headers = _headers(attacker_token, attacker.get("headers", {}))
            victim_body = ep.get("victim_body")
            attacker_body = ep.get("attacker_body", victim_body)

            url = urljoin(base_url, path)
            start = time.time()
            v_resp = requests.request(
                method,
                url,
                headers=victim_headers,
                json=victim_body,
                timeout=timeout,
            )
            a_resp = requests.request(
                method,
                url,
                headers=attacker_headers,
                json=attacker_body,
                timeout=timeout,
            )
            elapsed = int((time.time() - start) * 1000)

            vulnerable = v_resp.status_code == 200 and a_resp.status_code == 200
            reason = "attacker received 200 on victim resource" if vulnerable else "attacker denied"

            finding = Finding(
                endpoint=path,
                method=method,
                victim_status=v_resp.status_code,
                attacker_status=a_resp.status_code,
                vulnerable=vulnerable,
                reason=reason,
                elapsed_ms=elapsed,
            )
            out.write(json.dumps(finding.to_dict()) + "\n")
    print(f"wrote {out_path}")
    return 0
