from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


STATE_VERSION = 3


def default_state() -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "channels": {},
        "agent_profiles": {},
        "identity_profiles": {},
        "avatar_uploads": {},
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

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize cross-process read/modify/write state transactions."""

        self.ensure()
        lock_path = self.directory / "state.lock"
        with lock_path.open("a+", encoding="utf-8") as lock:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

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
