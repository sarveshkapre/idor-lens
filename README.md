# IDOR Lens

IDOR detector via role/token differential testing with minimal proof output.

## Scope (v0.1.0)

- YAML-driven test spec.
- Victim vs attacker token comparison.
- JSONL report output.

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m idor_lens run --spec spec.yml --out idor-report.jsonl
```

Tips:

- Use `--out -` to stream JSONL to stdout.
- Use `--fail-on-vuln` for CI/regression.
- Use `--strict-body-match` to reduce false positives when attacker gets a different 2xx body.

## HTML report

```bash
python -m idor_lens report --in idor-report.jsonl --out idor-report.html
```

## Regression compare

Compare a baseline run to a new run and fail CI only when *new* vulnerabilities appear:

```bash
python -m idor_lens compare --baseline baseline.jsonl --current idor-report.jsonl --fail-on-new
```
