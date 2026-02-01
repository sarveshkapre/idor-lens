from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .compare import compare_jsonl, write_compare_output
from .jsonl import open_text_out
from .report import write_html_report
from .runner import run_test
from .template import SpecTemplateOptions, render_spec_template
from .validate import validate_spec


def _version_str() -> str:
    try:
        return version("idor-lens")
    except PackageNotFoundError:
        return "0.0.0+unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="idor-lens")
    parser.add_argument("--version", action="version", version=_version_str())

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="Run IDOR differential test")
    p_run.add_argument("--spec", required=True, help="Path to YAML spec file")
    p_run.add_argument(
        "--out", default="idor-report.jsonl", help="Output JSONL path, or '-' for stdout"
    )
    p_run.add_argument("--timeout", type=float, default=10.0)
    p_run.add_argument(
        "--max-bytes", type=int, default=1024 * 1024, help="Max bytes hashed per response"
    )
    p_run.add_argument(
        "--strict-body-match",
        action="store_true",
        help="Only flag vulnerability when attacker response body matches victim (best-effort)",
    )
    p_run.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="Exit non-zero if any vulnerabilities are found (CI/regression mode)",
    )
    p_run.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry count for transient errors and 429/502/503/504 (default: 0)",
    )
    p_run.add_argument(
        "--retry-backoff",
        type=float,
        default=0.25,
        help="Seconds for exponential backoff base between retries (default: 0.25)",
    )
    p_run.add_argument(
        "--proxy", help="Proxy URL for both victim and attacker (e.g. http://127.0.0.1:8080)"
    )
    p_run.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (useful for local/self-signed targets)",
    )
    g_redirects = p_run.add_mutually_exclusive_group()
    g_redirects.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects (default: disabled to reduce false positives)",
    )
    g_redirects.add_argument(
        "--no-follow-redirects",
        action="store_true",
        help="Do not follow HTTP redirects",
    )
    p_run.set_defaults(func=_run)

    p_report = sub.add_parser("report", help="Render an HTML report from a JSONL run output")
    p_report.add_argument(
        "--in", dest="in_path", required=True, help="Input JSONL path, or '-' for stdin"
    )
    p_report.add_argument(
        "--out",
        dest="out_path",
        default="idor-report.html",
        help="Output HTML path, or '-' for stdout",
    )
    p_report.add_argument("--title", default="IDOR Lens Report")
    p_report.set_defaults(func=_report)

    p_compare = sub.add_parser(
        "compare", help="Compare baseline vs current JSONL (regression mode)"
    )
    p_compare.add_argument("--baseline", required=True, help="Baseline JSONL path")
    p_compare.add_argument("--current", required=True, help="Current JSONL path, or '-' for stdin")
    p_compare.add_argument(
        "--out", default="-", help="Write summary to this path (default: stdout)"
    )
    p_compare.add_argument(
        "--json", action="store_true", help="Write machine-readable JSON summary"
    )
    p_compare.add_argument(
        "--min-confidence",
        default="medium",
        choices=["none", "medium", "high"],
        help="Treat vulnerabilities below this confidence as non-vulnerable",
    )
    p_compare.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit non-zero if new vulnerabilities appear vs baseline",
    )
    p_compare.set_defaults(func=_compare)

    p_init = sub.add_parser("init", help="Write a sample YAML spec")
    p_init.add_argument("--out", default="spec.yml", help="Path to write, or '-' for stdout")
    p_init.add_argument(
        "--base-url", default="https://example.test", help="Base URL for target service"
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists",
    )
    p_init.set_defaults(func=_init)

    p_validate = sub.add_parser("validate", help="Validate a YAML spec without running requests")
    p_validate.add_argument("--spec", required=True, help="Path to YAML spec file")
    p_validate.add_argument(
        "--require-env",
        action="store_true",
        help="Fail if any $VARS remain unexpanded after env substitution",
    )
    p_validate.set_defaults(func=_validate)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _run(args: argparse.Namespace) -> int:
    return run_test(
        Path(args.spec),
        Path(args.out),
        args.timeout,
        strict_body_match=bool(args.strict_body_match),
        fail_on_vuln=bool(args.fail_on_vuln),
        max_bytes=int(args.max_bytes),
        verify_tls=(False if bool(args.insecure) else None),
        proxy=(str(args.proxy) if args.proxy is not None else None),
        follow_redirects=(
            True
            if bool(args.follow_redirects)
            else False
            if bool(args.no_follow_redirects)
            else None
        ),
        retries=int(args.retries),
        retry_backoff_s=float(args.retry_backoff),
    )


def _report(args: argparse.Namespace) -> int:
    write_html_report(Path(args.in_path), Path(args.out_path), title=str(args.title))
    return 0


def _compare(args: argparse.Namespace) -> int:
    summary = compare_jsonl(
        Path(args.baseline),
        Path(args.current),
        min_confidence=str(args.min_confidence),
    )
    write_compare_output(summary, Path(args.out), as_json=bool(args.json))
    return 2 if (bool(args.fail_on_new) and summary.new_vulnerable) else 0


def _init(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    content = render_spec_template(SpecTemplateOptions(base_url=str(args.base_url)))

    if str(out_path) != "-" and out_path.exists() and not bool(args.force):
        raise SystemExit(f"refusing to overwrite existing file: {out_path} (use --force)")

    with open_text_out(out_path) as out:
        out.write(content)
    return 0


def _validate(args: argparse.Namespace) -> int:
    return validate_spec(Path(args.spec), require_env=bool(args.require_env))


if __name__ == "__main__":
    raise SystemExit(main())
