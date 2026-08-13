from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from .config import HEX64_RE


class CommandError(RuntimeError):
    pass


def _decode_json(output: str, label: str) -> Any:
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise CommandError(f"{label} returned invalid JSON: {exc}") from exc


@dataclass
class HerdrClient:
    binary: str

    def _run(self, args: list[str], timeout: int = 30) -> Any:
        try:
            result = subprocess.run(
                [self.binary, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandError(f"failed to run Herdr: {exc}") from exc
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise CommandError(f"Herdr command failed: {message}")
        return _decode_json(result.stdout, "Herdr")

    def snapshot(self) -> dict[str, Any]:
        response = self._run(["api", "snapshot"])
        try:
            return response["result"]["snapshot"]
        except (KeyError, TypeError) as exc:
            raise CommandError("Herdr snapshot response is missing result.snapshot") from exc

    def prompt(self, pane_id: str, text: str) -> None:
        self._run(["agent", "prompt", pane_id, text], timeout=15)

    def interrupt(self, pane_id: str) -> None:
        self._run(["agent", "send-keys", pane_id, "ctrl+c"], timeout=10)


@dataclass
class BuzzClient:
    binary: str
    relay_url: str
    private_key: str
    auth_tag: str | None = None

    def _run(self, args: list[str], input_text: str | None = None, timeout: int = 30) -> Any:
        env = os.environ.copy()
        env["BUZZ_RELAY_URL"] = self.relay_url
        env["BUZZ_PRIVATE_KEY"] = self.private_key
        if self.auth_tag:
            env["BUZZ_AUTH_TAG"] = self.auth_tag
        else:
            env.pop("BUZZ_AUTH_TAG", None)
        try:
            result = subprocess.run(
                [self.binary, *args],
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=timeout,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandError(f"failed to run Buzz CLI: {exc}") from exc
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            try:
                parsed = json.loads(message)
                message = str(parsed.get("message") or parsed.get("error") or message)
            except json.JSONDecodeError:
                pass
            raise CommandError(f"Buzz command failed: {message}")
        return _decode_json(result.stdout, "Buzz")

    def list_channels(self) -> list[dict[str, Any]]:
        result = self._run(["channels", "list", "--limit", "500"])
        return result if isinstance(result, list) else []

    def create_channel(
        self, name: str, channel_type: str, visibility: str, description: str
    ) -> dict[str, Any]:
        result = self._run(
            [
                "channels",
                "create",
                "--name",
                name,
                "--type",
                channel_type,
                "--visibility",
                visibility,
                "--description",
                description,
            ]
        )
        return result if isinstance(result, dict) else {}

    def update_channel(self, channel_id: str, name: str, description: str) -> dict[str, Any]:
        result = self._run(
            [
                "channels",
                "update",
                "--channel",
                channel_id,
                "--name",
                name,
                "--description",
                description,
            ]
        )
        return result if isinstance(result, dict) else {}

    def archive_channel(self, channel_id: str) -> dict[str, Any]:
        result = self._run(["channels", "archive", "--channel", channel_id])
        return result if isinstance(result, dict) else {}

    def members(self, channel_id: str) -> list[dict[str, Any]]:
        result = self._run(["channels", "members", "--channel", channel_id])
        return result if isinstance(result, list) else []

    def add_member(self, channel_id: str, pubkey: str, role: str = "bot") -> dict[str, Any]:
        if role not in {"owner", "admin", "member", "guest", "bot"}:
            raise CommandError(f"invalid Buzz channel role: {role}")
        result = self._run(
            [
                "channels",
                "add-member",
                "--channel",
                channel_id,
                "--pubkey",
                pubkey,
                "--role",
                role,
            ]
        )
        return result if isinstance(result, dict) else {}

    def upload_file(self, path: Path) -> dict[str, Any]:
        result = self._run(
            ["upload", "file", "--file", str(path)],
            timeout=150,
        )
        return result if isinstance(result, dict) else {}

    def set_profile(
        self,
        name: str,
        about: str,
        avatar: str | None = None,
    ) -> dict[str, Any]:
        args = ["users", "set-profile", "--name", name, "--about", about]
        if avatar:
            args.extend(["--avatar", avatar])
        result = self._run(args)
        return result if isinstance(result, dict) else {}

    def messages(self, channel_id: str, since: int) -> list[dict[str, Any]]:
        result = self._run(
            [
                "messages",
                "get",
                "--channel",
                channel_id,
                "--since",
                str(since),
                "--limit",
                "200",
            ]
        )
        return result if isinstance(result, list) else []

    def send_reply(self, channel_id: str, event_id: str, content: str) -> dict[str, Any]:
        result = self._run(
            [
                "messages",
                "send",
                "--channel",
                channel_id,
                "--reply-to",
                event_id,
                "--content",
                "-",
            ],
            input_text=content,
        )
        return result if isinstance(result, dict) else {}


@dataclass
class NostrTools:
    """Small, secret-safe wrapper around nak for keys and profile events."""

    binary: str

    def _run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        env_updates: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> str:
        env = os.environ.copy()
        if env_updates:
            env.update(env_updates)
        try:
            result = subprocess.run(
                [self.binary, *args],
                check=False,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=timeout,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandError(f"failed to run nak: {exc}") from exc
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise CommandError(f"nak command failed: {message}")
        return result.stdout.strip()

    def generate_keypair(self) -> tuple[str, str]:
        private_key = self._run(["key", "generate"])
        if not HEX64_RE.fullmatch(private_key):
            raise CommandError("nak returned an invalid secret key")
        public_key = self.public_key(private_key)
        return private_key, public_key

    def public_key(self, private_key: str) -> str:
        if not HEX64_RE.fullmatch(private_key):
            raise CommandError("invalid secret key")
        public_key = self._run(["key", "public"], input_text=private_key + "\n")
        if not HEX64_RE.fullmatch(public_key):
            raise CommandError("nak returned an invalid public key")
        return public_key

    def publish_profile(
        self,
        relay_url: str,
        private_key: str,
        *,
        name: str,
        about: str,
        picture: str | None = None,
    ) -> None:
        if not HEX64_RE.fullmatch(private_key):
            raise CommandError("refusing to publish with an invalid private key")
        profile = {"name": name, "display_name": name, "about": about}
        if picture:
            profile["picture"] = picture
        content = json.dumps(profile, separators=(",", ":"), sort_keys=True)
        # The key travels only in the child environment, never argv or logs.
        self._run(
            ["event", "--auth", "--kind", "0", "--content", content, relay_url],
            env_updates={"NOSTR_SECRET_KEY": private_key},
            timeout=45,
        )

    def publish_agent_profile(
        self,
        relay_url: str,
        private_key: str,
        content: dict[str, Any],
    ) -> None:
        """Publish a replaceable Buzz agent-directory event (kind:10100)."""

        if not HEX64_RE.fullmatch(private_key):
            raise CommandError("refusing to publish with an invalid private key")
        encoded = json.dumps(content, separators=(",", ":"), sort_keys=True)
        # The key travels only in the child environment, never argv or logs.
        self._run(
            ["event", "--auth", "--kind", "10100", "--content", encoded, relay_url],
            env_updates={"NOSTR_SECRET_KEY": private_key},
            timeout=45,
        )


@dataclass
class LocalBuzzAdmin:
    """Trusted local relay administration through its Compose services."""

    compose_file: Path
    relay_service: str = "relay"
    postgres_service: str = "postgres"
    postgres_user: str = "buzz"
    postgres_database: str = "buzz"
    docker_binary: str = "docker"

    def _compose(self, service: str, args: list[str], timeout: int = 45) -> str:
        try:
            result = subprocess.run(
                [
                    self.docker_binary,
                    "compose",
                    "-f",
                    str(self.compose_file),
                    "exec",
                    "-T",
                    service,
                    *args,
                ],
                cwd=self.compose_file.parent,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandError(f"failed to run local Buzz admin command: {exc}") from exc
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            raise CommandError(f"local Buzz admin command failed: {message}")
        return result.stdout.strip()

    def add_relay_member(self, pubkey: str) -> None:
        if not HEX64_RE.fullmatch(pubkey):
            raise CommandError("invalid pubkey for relay membership")
        self._compose(
            self.relay_service,
            ["buzz-admin", "add-member", "--pubkey", pubkey, "--role", "member"],
        )

    def relay_member_pubkeys(self) -> set[str]:
        output = self._compose(self.relay_service, ["buzz-admin", "list-members"])
        return {
            line.split()[0].lower()
            for line in output.splitlines()
            if line.split() and HEX64_RE.fullmatch(line.split()[0].lower())
        }

    def _psql(self, sql: str) -> list[str]:
        output = self._compose(
            self.postgres_service,
            [
                "psql",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                self.postgres_user,
                "-d",
                self.postgres_database,
                "-Atc",
                sql,
            ],
        )
        return [line.strip() for line in output.splitlines() if line.strip()]

    def community_for_human(self, human_pubkey: str) -> str:
        if not HEX64_RE.fullmatch(human_pubkey):
            raise CommandError("invalid human pubkey")
        rows = self._psql(
            "SELECT DISTINCT community_id::text FROM ("
            "SELECT community_id FROM users WHERE pubkey = decode('"
            + human_pubkey
            + "','hex') AND deactivated_at IS NULL UNION ALL "
            "SELECT community_id FROM relay_members WHERE lower(pubkey) = '"
            + human_pubkey
            + "') q ORDER BY 1;"
        )
        if len(rows) != 1:
            raise CommandError(
                "human pubkey must resolve to exactly one local Buzz community "
                f"(found {len(rows)})"
            )
        try:
            UUID(rows[0])
        except ValueError as exc:
            raise CommandError("local Buzz returned an invalid community id") from exc
        return rows[0]

    def assign_agent_owner(self, human_pubkey: str, agent_pubkeys: list[str]) -> None:
        """Idempotently bind plugin-controlled identities to the human pubkey."""
        community_id = self.community_for_human(human_pubkey)
        for agent_pubkey in sorted(set(agent_pubkeys)):
            if agent_pubkey == human_pubkey:
                continue
            if not HEX64_RE.fullmatch(agent_pubkey):
                raise CommandError("invalid agent pubkey")
            # A kind:0 profile normally creates this row first. The insert makes
            # bootstrap deterministic if the relay's side-effect worker lags.
            rows = self._psql(
                "INSERT INTO users (community_id, pubkey) VALUES ('"
                + community_id
                + "'::uuid, decode('"
                + agent_pubkey
                + "','hex')) ON CONFLICT (community_id, pubkey) DO NOTHING; "
                "UPDATE users SET agent_owner_pubkey = decode('"
                + human_pubkey
                + "','hex'), updated_at = NOW() WHERE community_id = '"
                + community_id
                + "'::uuid AND pubkey = decode('"
                + agent_pubkey
                + "','hex') AND (agent_owner_pubkey IS NULL OR agent_owner_pubkey = decode('"
                + human_pubkey
                + "','hex')); "
                "SELECT COALESCE(encode(agent_owner_pubkey,'hex'),'') FROM users WHERE community_id = '"
                + community_id
                + "'::uuid AND pubkey = decode('"
                + agent_pubkey
                + "','hex');"
            )
            if not rows or rows[-1] != human_pubkey:
                raise CommandError(
                    f"agent {agent_pubkey[:12]} is already owned by another pubkey"
                )
