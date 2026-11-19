"""Session journal. The firewall snapshot is written here BEFORE any change is made,
so a crash at any point can always be undone with `phantomx stop`."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .config import write_json_atomic


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> dict | None:
        """The saved session, None if there is none.

        A damaged file must never make recovery impossible: it is moved aside (kept for
        diagnosis) and reported as {"_corrupt": True} with no snapshot, so `stop` falls back
        to restoring safe defaults instead of crashing."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (ValueError, UnicodeDecodeError, OSError):
            self._quarantine()
            return {"_corrupt": True}
        if not isinstance(data, dict):
            self._quarantine()
            return {"_corrupt": True}
        return data

    def _quarantine(self) -> None:
        try:
            self.path.replace(self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}"))
        except OSError:
            pass

    def save(self, state: dict) -> None:
        write_json_atomic(self.path, {k: v for k, v in state.items() if not k.startswith("_")})

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
