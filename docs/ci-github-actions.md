# GitHub Actions CI Examples

These are copy/paste templates intended for *consumer repos* that want to run IDOR Lens in CI.

## Inputs

- A spec file checked into the repo (example: `security/idor-spec.yml`)
- Two credential sets available as GitHub Actions secrets (example: `VICTIM_TOKEN`, `ATTACKER_TOKEN`)
- Optional: a committed baseline JSONL (example: `security/idor-baseline.jsonl`)

## Example: Fail CI On Any Vulnerability

```yaml
name: idor-lens

on:
  workflow_dispatch:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      # Install IDOR Lens. If you're using a released package, replace with:
      #   pip install idor-lens
      - run: pip install "git+https://github.com/sarveshkapre/idor-lens@<PINNED_SHA>"

      - name: Validate spec
        run: python -m idor_lens validate --spec security/idor-spec.yml --require-env
        env:
          VICTIM_TOKEN: ${{ secrets.VICTIM_TOKEN }}
          ATTACKER_TOKEN: ${{ secrets.ATTACKER_TOKEN }}

      - name: Run scan (fail on vuln)
        run: python -m idor_lens run --spec security/idor-spec.yml --out idor-report.jsonl --fail-on-vuln
        env:
          VICTIM_TOKEN: ${{ secrets.VICTIM_TOKEN }}
          ATTACKER_TOKEN: ${{ secrets.ATTACKER_TOKEN }}

      - name: Write SARIF
        if: always()
        run: python -m idor_lens sarif --in idor-report.jsonl --out idor-report.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: idor-report.sarif
```

## Example: Regression Mode (Fail Only On New Vulnerabilities)

This is useful when you have existing known findings and want CI to fail only on regressions.

```yaml
name: idor-lens-regression

on:
  workflow_dispatch:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install "git+https://github.com/sarveshkapre/idor-lens@<PINNED_SHA>"

      - name: Run scan
        run: python -m idor_lens run --spec security/idor-spec.yml --out idor-current.jsonl
        env:
          VICTIM_TOKEN: ${{ secrets.VICTIM_TOKEN }}
          ATTACKER_TOKEN: ${{ secrets.ATTACKER_TOKEN }}

      - name: Compare against baseline (fail on new)
        run: python -m idor_lens compare --baseline security/idor-baseline.jsonl --current idor-current.jsonl --fail-on-new

      - name: Write SARIF (current run)
        if: always()
        run: python -m idor_lens sarif --in idor-current.jsonl --out idor-current.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: idor-current.sarif
```

