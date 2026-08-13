from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


STATE_VERSION = 2


def default_state() -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "channels": {},
        "agent_profiles": {},
        "last_seen": {},
        "processed": [],
        "pending": [],
        "reply_contexts": {},
        "last_error": None,
        "last_reconcile_at": None,
    }


class StateStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "state.json"

    def ensure(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass

    def load(self) -> dict[str, Any]:
        self.ensure()
        if not self.path.exists():
            return default_state()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default_state()
        base = default_state()
        if isinstance(value, dict):
            base.update(value)
        base["version"] = STATE_VERSION
        return base

    def save(self, state: dict[str, Any]) -> None:
        self.ensure()
        fd, temporary = tempfile.mkstemp(prefix="state-", suffix=".json", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def runtime_directory() -> Path:
    override = os.environ.get("BUZZR_RUNTIME_DIR") or os.environ.get("HERDR_BUZZ_RUNTIME_DIR")
    if override:
        return Path(override)
    return Path("/tmp") / f"buzzr-{os.getuid()}"
