from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "idor_lens", "--help"], check=False)
    assert proc.returncode == 0


def test_cli_run_with_json_ignore_paths_smoke(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            if self.path != "/items/123":
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return

            auth = self.headers.get("Authorization")
            ts = time.time()
            body = {
                "id": 123,
                "secret": "S",
                "updatedAt": ts if auth == "Bearer victim" else ts + 1,
            }
            data = json.dumps(body).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    _addr, port = sock.getsockname()
    sock.close()

    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        spec = tmp_path / "spec.yml"
        out = tmp_path / "out.jsonl"
        spec.write_text(
            "base_url: "
            + base_url
            + "\n"
            + "json_ignore_paths:\n"
            + "  - /updatedAt\n"
            + "victim:\n  auth: Bearer victim\n"
            + "attacker:\n  auth: Bearer attacker\n"
            + "endpoints:\n  - path: /items/123\n    method: GET\n",
            encoding="utf-8",
        )

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "idor_lens",
                "run",
                "--spec",
                str(spec),
                "--out",
                str(out),
                "--strict-body-match",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

        row = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
        assert row["vulnerable"] is True
        assert row["body_match"] is True
    finally:
        server.shutdown()


def test_cli_replay_by_name_smoke(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            if self.path not in ("/items/1", "/items/2"):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    _addr, port = sock.getsockname()
    sock.close()

    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        spec = tmp_path / "spec.yml"
        out = tmp_path / "out.jsonl"
        spec.write_text(
            "base_url: "
            + base_url
            + "\n"
            + "victim:\n  auth: Bearer victim\n"
            + "attacker:\n  auth: Bearer attacker\n"
            + "endpoints:\n"
            + "  - name: one\n    path: /items/1\n    method: GET\n"
            + "  - name: two\n    path: /items/2\n    method: GET\n",
            encoding="utf-8",
        )

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "idor_lens",
                "replay",
                "--spec",
                str(spec),
                "--name",
                "two",
                "--out",
                str(out),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr

        row = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
        assert row["endpoint"] == "/items/2"
        assert row["name"] == "two"
    finally:
        server.shutdown()
