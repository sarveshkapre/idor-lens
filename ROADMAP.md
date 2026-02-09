# ROADMAP

## v0.1.0

- Differential IDOR runner + JSONL report.

## Next

- Rely less on status-only signals: richer allow/deny heuristics for noisy apps (2xx denial pages, 404-on-deny patterns).
- Parametrized endpoint matrices (intruder-style ID substitution over path/query/body) to increase coverage.
- Lightweight endpoint batching/parallelism with rate-limit-aware controls.
- Optional token refresh command helpers (building on `auth_file`).
