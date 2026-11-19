"""Session journal. The firewall snapshot is written here BEFORE any change is made,
so a crash at any point can always be undone with `phantomx stop`."""
from __future__ import annotations

import json
from pathlib import Path

from .config import write_json_atomic


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> dict | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        return data if isinstance(data, dict) else None

    def save(self, state: dict) -> None:
        write_json_atomic(self.path, state)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
