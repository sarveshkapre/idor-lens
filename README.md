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
