from __future__ import annotations

import argparse
from pathlib import Path

from .runner import run_test


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="idor-lens")
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="Run IDOR differential test")
    p_run.add_argument("--spec", required=True, help="Path to YAML spec file")
    p_run.add_argument("--out", default="idor-report.jsonl")
    p_run.add_argument("--timeout", type=float, default=10.0)
    p_run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _run(args: argparse.Namespace) -> int:
    return run_test(Path(args.spec), Path(args.out), args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
