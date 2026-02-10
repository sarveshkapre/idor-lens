from __future__ import annotations

import json
from pathlib import Path

from idor_lens.schema import spec_schema


def test_docs_schema_is_in_sync() -> None:
    path = Path("docs/idor-lens.schema.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == spec_schema()
