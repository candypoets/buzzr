from __future__ import annotations

import json
import os
import fcntl
import secrets
import shlex
import signal
import time
import uuid
from pathlib import Path
from typing import Any

from .clients import BuzzClient, CommandError, HerdrClient
from .config import Config
from .config import load_config
from .provisioning import provision_local
from .state import StateStore, runtime_directory
from .sync import reconcile
from .topology import AgentBinding, Topology, build_topology, mentioned_pubkeys


READY_STATES = {"idle", "done"}


def _author_allowed(config: Config, author: str) -> bool:
    mode = config.bridge.respond_to
    author = author.lower()
    if mode == "anyone":
        return True
    if mode == "nobody":
        return False
    owner = config.owner_public_key() or ""
    if mode == "owner-only":
        return bool(owner and author == owner)
    allowed = {value.lower() for value in config.bridge.respond_to_allowlist}
    if owner:
        allowed.add(owner)
    return author in allowed


class BridgeService:
    def __init__(
        self,
        config: Config,
        store: StateStore,
        plugin_root: Path,
        config_path: Path | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.plugin_root = plugin_root
        self.config_path = config_path
        self.herdr = HerdrClient(config.bridge.herdr_bin)
        self.runtime_dir = runtime_directory()
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.outbox_dir = self.runtime_dir / "outbox"
        self.outbox_dir.mkdir(mode=0o700, exist_ok=True)
        self.running = True

    def stop(self, *_args: object) -> None:
        self.running = False

    def _identity_client(self, identity_id: str) -> BuzzClient | None:
        private_key, auth_tag = self.config.identity_credentials(identity_id)
        if not private_key:
            return None
        return BuzzClient(
            self.config.bridge.buzz_bin,
            self.config.bridge.relay_url,
            private_key,
            auth_tag,
        )

    def _reply_command(self, token: str) -> str:
        executable = self.plugin_root / "bin" / "buzzr"
        return (
            f"printf '%s' '<your reply>' | {shlex.quote(str(executable))} "
            f"reply --token {shlex.quote(token)} --content -"
        )

    def _dispatch(self, binding: AgentBinding, event: dict[str, Any], state: dict[str, Any]) -> bool:
        token = secrets.token_urlsafe(24)
        event_id = str(event.get("id", ""))
        channel = state["channels"].get(binding.workspace_id, {})
        channel_id = channel.get("channel_id") if isinstance(channel, dict) else None
        if not channel_id or not binding.identity_id:
            return False
        state["reply_contexts"][token] = {
            "identity_id": binding.identity_id,
            "channel_id": channel_id,
            "event_id": event_id,
            "workspace_id": binding.workspace_id,
            "pane_id": binding.pane_id,
            "created_at": int(time.time()),
        }
        content = str(event.get("content", ""))
        author = str(event.get("pubkey", ""))
        prompt = (
            "[Buzz bridge]\n"
            f"Space: {binding.workspace_label}\n"
            f"Buzz channel: #{binding.channel_name}\n"
            f"Buzz event: {event_id}\n"
            f"Author pubkey: {author}\n\n"
            f"{content}\n\n"
            "When you have a useful answer, you MUST publish it back to the originating "
            "Buzz thread. Replace <your reply> and run exactly this local bridge command; "
            "it does not expose Buzz credentials:\n"
            f"{self._reply_command(token)}"
        )
        try:
            self.herdr.prompt(binding.pane_id, prompt)
        except CommandError:
            state["reply_contexts"].pop(token, None)
            return False
        return True

    def _process_outbox(self, state: dict[str, Any]) -> None:
        for request_path in sorted(self.outbox_dir.glob("*.request.json")):
            result_path = request_path.with_name(request_path.name.replace(".request.json", ".result.json"))
            try:
                request = json.loads(request_path.read_text(encoding="utf-8"))
                token = str(request.get("token", ""))
                content = str(request.get("content", ""))
                context = state["reply_contexts"].get(token)
                if not isinstance(context, dict):
                    raise CommandError("reply token is unknown, expired, or already used")
                if not content.strip():
                    raise CommandError("reply content is empty")
                if len(content.encode("utf-8")) > 65_535:
                    raise CommandError("reply content exceeds 65,535 bytes")
                identity_id = str(context["identity_id"])
                client = self._identity_client(identity_id)
                if not client:
                    raise CommandError(f"private key for identity {identity_id!r} is unavailable")
                response = client.send_reply(
                    str(context["channel_id"]),
                    str(context["event_id"]),
                    content,
                )
                state["reply_contexts"].pop(token, None)
                result = {"ok": True, "response": response}
            except (OSError, json.JSONDecodeError, KeyError, CommandError) as exc:
                result = {"ok": False, "error": str(exc)}
            temporary = result_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(result), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, result_path)
            try:
                request_path.unlink()
            except OSError:
                pass

    def _poll_messages(self, topology: Topology, state: dict[str, Any]) -> None:
        now = int(time.time())
        processed = set(state.get("processed", []))
        for binding in topology.agents:
            if not binding.identity_id or not binding.public_key:
                continue
            channel = state["channels"].get(binding.workspace_id, {})
            channel_id = channel.get("channel_id") if isinstance(channel, dict) else None
            if not channel_id:
                continue
            client = self._identity_client(binding.identity_id)
            if not client:
                continue
            cursor_key = f"{channel_id}:{binding.identity_id}"
            since = int(state["last_seen"].get(cursor_key, now - 2))
            try:
                events = client.messages(channel_id, since)
            except CommandError:
                continue
            newest = since
            for event in sorted(events, key=lambda item: int(item.get("created_at", 0))):
                newest = max(newest, int(event.get("created_at", 0)))
                event_id = str(event.get("id", ""))
                if not event_id or event_id in processed:
                    continue
                if str(event.get("pubkey", "")).lower() == binding.public_key:
                    processed.add(event_id)
                    continue
                if binding.public_key not in mentioned_pubkeys(event):
                    continue
                if not _author_allowed(self.config, str(event.get("pubkey", ""))):
                    processed.add(event_id)
                    continue
                content = str(event.get("content", "")).strip()
                if content == "!cancel":
                    try:
                        self.herdr.interrupt(binding.pane_id)
                    except CommandError:
                        pass
                    processed.add(event_id)
                    continue
                if binding.status not in READY_STATES:
                    continue
                if self._dispatch(binding, event, state):
                    processed.add(event_id)
            state["last_seen"][cursor_key] = newest
        state["processed"] = list(processed)[-5000:]

    def run(self) -> None:
        lock_path = self.runtime_dir / "daemon.lock"
        pid_path = self.runtime_dir / "daemon.pid"
        with lock_path.open("a+", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CommandError("buzzr daemon is already running") from exc
            pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
            os.chmod(pid_path, 0o600)
            signal.signal(signal.SIGTERM, self.stop)
            signal.signal(signal.SIGINT, self.stop)
            last_message_poll = 0.0
            try:
                while self.running:
                    try:
                        if self.config_path:
                            self.config = load_config(self.config_path)
                            self.herdr = HerdrClient(self.config.bridge.herdr_bin)
                        snapshot = self.herdr.snapshot()
                        topology = build_topology(snapshot, self.config)
                        if (
                            self.config.bridge.auto_provision_agents
                            and any(not agent.identity_id for agent in topology.agents)
                        ):
                            if not self.config_path:
                                raise CommandError(
                                    "automatic provisioning requires a persistent config path"
                                )
                            self.config, topology, _report = provision_local(
                                self.config_path, snapshot
                            )
                        reconcile(self.config, topology, self.store)
                        with self.store.locked():
                            state = self.store.load()
                            self._process_outbox(state)
                            now = time.monotonic()
                            if self.config.bridge.routing_enabled and (
                                now - last_message_poll
                                >= self.config.bridge.message_poll_seconds
                            ):
                                self._poll_messages(topology, state)
                                last_message_poll = now
                            state["last_error"] = None
                            self.store.save(state)
                    except Exception as exc:  # daemon boundary: record and retry
                        with self.store.locked():
                            state = self.store.load()
                            state["last_error"] = str(exc)
                            self.store.save(state)
                    deadline = time.monotonic() + self.config.bridge.poll_seconds
                    while self.running and time.monotonic() < deadline:
                        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            finally:
                pid_path.unlink(missing_ok=True)


def queue_reply(token: str, content: str, timeout: float = 30.0) -> dict[str, Any]:
    runtime_dir = runtime_directory()
    outbox = runtime_dir / "outbox"
    outbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    request_id = uuid.uuid4().hex
    request_path = outbox / f"{request_id}.request.json"
    result_path = outbox / f"{request_id}.result.json"
    temporary = outbox / f"{request_id}.tmp"
    temporary.write_text(json.dumps({"token": token, "content": content}), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, request_path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result_path.exists():
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result_path.unlink(missing_ok=True)
            return result
        time.sleep(0.1)
    raise CommandError("bridge daemon did not acknowledge the reply within 30 seconds")
