# ROADMAP

## v0.1.0

- Differential IDOR runner + JSONL report.

## Next

- Rely less on status-only signals: continue expanding allow/deny heuristics for noisy apps (2xx denial pages, 404-on-deny patterns).
- Lightweight endpoint batching/parallelism with rate-limit-aware controls.
- Optional token refresh command helpers (building on `auth_file`).
- Expand matrix ergonomics (tag filters, richer variable controls) now that baseline path/query/body matrix support exists.
