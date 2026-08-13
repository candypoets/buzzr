from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(ValueError):
    """Raised when bridge configuration is unsafe or invalid."""


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


@dataclass(frozen=True)
class IdentityConfig:
    identity_id: str
    display_name: str
    aliases: tuple[str, ...]
    public_key: str
    private_key_env: str
    auth_tag_env: str | None = None

    @property
    def normalized_aliases(self) -> frozenset[str]:
        values = {normalize_name(self.identity_id), normalize_name(self.display_name)}
        values.update(normalize_name(alias) for alias in self.aliases)
        return frozenset(value for value in values if value)


@dataclass(frozen=True)
class BridgeConfig:
    relay_url: str = "wss://buzz.nuts.cash"
    buzz_bin: str = "buzz"
    herdr_bin: str = "herdr"
    nak_bin: str = "nak"
    secrets_files: tuple[Path, ...] = ()
    managed_secrets_file: Path | None = None
    bridge_private_key_env: str = "BUZZR_BRIDGE_PRIVATE_KEY"
    bridge_auth_tag_env: str | None = None
    bridge_public_key: str | None = None
    human_pubkey: str | None = None
    compose_file: Path | None = None
    relay_service: str = "relay"
    postgres_service: str = "postgres"
    postgres_user: str = "buzz"
    postgres_database: str = "buzz"
    include_spaces: tuple[str, ...] = ("*",)
    exclude_spaces: tuple[str, ...] = ("~",)
    channel_type: str = "stream"
    channel_visibility: str = "private"
    channel_description: str = "Mirrored from Herdr Space {space}."
    sync_enabled: bool = False
    routing_enabled: bool = False
    archive_closed_spaces: bool = False
    remove_departed_agents: bool = False
    respond_to: str = "owner-only"
    respond_to_allowlist: tuple[str, ...] = ()
    poll_seconds: float = 5.0
    message_poll_seconds: float = 2.0
    auto_provision_agents: bool = False
    avatars_enabled: bool = True
    avatar_pack: str = "bees-v1"
    avatar_pack_path: Path | None = None

    # Compatibility accessors for the pre-buzzr 0.3 configuration schema.
    @property
    def secrets_file(self) -> Path | None:
        return self.secrets_files[0] if self.secrets_files else None

    @property
    def owner_private_key_env(self) -> str:
        return self.bridge_private_key_env

    @property
    def owner_auth_tag_env(self) -> str | None:
        return self.bridge_auth_tag_env

    @property
    def owner_pubkey(self) -> str | None:
        return self.human_pubkey


@dataclass
class Config:
    bridge: BridgeConfig
    identities: dict[str, IdentityConfig] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict, repr=False)

    def secret(self, env_name: str | None) -> str | None:
        if not env_name:
            return None
        return os.environ.get(env_name) or self.secrets.get(env_name)

    def bridge_credentials(self) -> tuple[str | None, str | None]:
        return (
            self.secret(self.bridge.bridge_private_key_env),
            self.secret(self.bridge.bridge_auth_tag_env),
        )

    def owner_credentials(self) -> tuple[str | None, str | None]:
        """Compatibility alias: the old 'owner' signer is now the bridge signer."""
        return self.bridge_credentials()

    def human_public_key(self) -> str | None:
        """Return the human controller pubkey, with legacy NIP-OA inference."""
        if self.bridge.human_pubkey:
            return self.bridge.human_pubkey.lower()
        _private_key, auth_tag = self.bridge_credentials()
        if not auth_tag:
            return None
        try:
            value = json.loads(auth_tag)
        except json.JSONDecodeError:
            return None
        if (
            isinstance(value, list)
            and len(value) == 4
            and value[0] == "auth"
            and isinstance(value[1], str)
            and HEX64_RE.fullmatch(value[1].lower())
        ):
            return value[1].lower()
        return None

    def owner_public_key(self) -> str | None:
        """Compatibility alias for human_public_key()."""
        return self.human_public_key()

    def identity_credentials(self, identity_id: str) -> tuple[str | None, str | None]:
        identity = self.identities[identity_id]
        return self.secret(identity.private_key_env), self.secret(identity.auth_tag_env)

    def first_reader_credentials(self) -> tuple[str | None, str | None]:
        bridge_key, bridge_auth = self.bridge_credentials()
        if bridge_key:
            return bridge_key, bridge_auth
        for identity_id in sorted(self.identities):
            key, auth = self.identity_credentials(identity_id)
            if key:
                return key, auth
        return None, None

    def reader_credentials(self) -> list[tuple[str | None, str, str | None]]:
        """All available signers, ordered with the bridge first."""
        result: list[tuple[str | None, str, str | None]] = []
        bridge_key, bridge_auth = self.bridge_credentials()
        if bridge_key:
            result.append((self.bridge.bridge_public_key, bridge_key, bridge_auth))
        for identity_id in sorted(self.identities):
            key, auth = self.identity_credentials(identity_id)
            if key:
                result.append((self.identities[identity_id].public_key, key, auth))
        return result


def _as_tuple(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError("expected an array of strings")
    return tuple(value)


def parse_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        raise ConfigError(f"secrets file does not exist: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ConfigError(f"secrets file must not be group/world accessible: {path} (mode {mode:o})")

    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ConfigError(f"invalid secrets line {line_number} in {path}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigError(f"invalid environment name on line {line_number} in {path}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    # JSON basic strings are also valid TOML basic strings for the values used
    # by this configuration file.
    return json.dumps(value, ensure_ascii=False)


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f"{path.stem}-", suffix=path.suffix, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update_bridge_settings(path: Path, updates: dict[str, Any | None]) -> None:
    """Atomically update keys in [bridge] without touching identity tables."""
    if not path.exists():
        raise ConfigError(f"configuration not found: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    bridge_start: int | None = None
    bridge_end = len(lines)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[bridge]":
            bridge_start = index
            continue
        if bridge_start is not None and index > bridge_start and stripped.startswith("["):
            bridge_end = index
            break
    if bridge_start is None:
        lines = ["[bridge]", *lines]
        bridge_start = 0
        bridge_end = 1

    remaining = dict(updates)
    rewritten: list[str] = []
    key_pattern = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=")
    for index, line in enumerate(lines):
        if bridge_start < index < bridge_end:
            match = key_pattern.match(line.strip())
            if match and match.group(1) in remaining:
                key = match.group(1)
                value = remaining.pop(key)
                if value is not None:
                    rewritten.append(f"{key} = {_toml_value(value)}")
                continue
        rewritten.append(line)

    # Re-find the end after replacements/removals and append new keys before
    # the next TOML table.
    insertion = len(rewritten)
    found_bridge = False
    for index, line in enumerate(rewritten):
        stripped = line.strip()
        if stripped == "[bridge]":
            found_bridge = True
            continue
        if found_bridge and stripped.startswith("["):
            insertion = index
            break
    additions = [
        f"{key} = {_toml_value(value)}"
        for key, value in remaining.items()
        if value is not None
    ]
    if additions:
        rewritten[insertion:insertion] = additions

    _atomic_write(path, "\n".join(rewritten).rstrip() + "\n")


def append_identities(path: Path, identities: Iterable[IdentityConfig]) -> None:
    """Append newly generated identity tables without rewriting user configuration."""
    if not path.exists():
        raise ConfigError(f"configuration not found: {path}")
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    existing = raw.get("identities", {})
    if not isinstance(existing, dict):
        raise ConfigError("[identities] must be a table")
    blocks: list[str] = []
    for identity in identities:
        if identity.identity_id in existing:
            continue
        if normalize_name(identity.identity_id) != identity.identity_id:
            raise ConfigError(f"identity id must be normalized: {identity.identity_id}")
        blocks.extend(
            [
                f"[identities.{identity.identity_id}]",
                f"display_name = {_toml_value(identity.display_name)}",
                f"aliases = {_toml_value(list(identity.aliases))}",
                f"public_key = {_toml_value(identity.public_key)}",
                f"private_key_env = {_toml_value(identity.private_key_env)}",
                "",
            ]
        )
    if not blocks:
        return
    content = path.read_text(encoding="utf-8").rstrip() + "\n\n" + "\n".join(blocks).rstrip() + "\n"
    _atomic_write(path, content)


def update_dotenv(path: Path, updates: dict[str, str]) -> None:
    """Atomically add or replace literal dotenv values in a private file."""
    values = parse_dotenv(path) if path.exists() else {}
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigError(f"invalid environment name: {key}")
        if "\n" in value or "\r" in value:
            raise ConfigError(f"dotenv value for {key} contains a newline")
        values[key] = value
    content = "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
    _atomic_write(path, content)


def load_config(path: Path) -> Config:
    if not path.exists():
        raise ConfigError(f"configuration not found: {path}; run `buzzr init-config`")
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    bridge_raw = raw.get("bridge", {})
    if not isinstance(bridge_raw, dict):
        raise ConfigError("[bridge] must be a table")

    secrets_override = os.environ.get("BUZZR_SECRETS_FILE") or os.environ.get(
        "HERDR_BUZZ_SECRETS_FILE"
    )
    secret_values: list[str]
    if secrets_override:
        secret_values = [secrets_override]
    elif "secrets_files" in bridge_raw:
        secret_values = list(_as_tuple(bridge_raw.get("secrets_files"), ()))
    elif bridge_raw.get("secrets_file"):
        secret_values = [str(bridge_raw["secrets_file"])]
    else:
        secret_values = []

    secrets_files: list[Path] = []
    secrets: dict[str, str] = {}
    for raw_path in secret_values:
        secret_path = Path(raw_path).expanduser()
        if not secret_path.is_absolute():
            secret_path = path.parent / secret_path
        secret_path = secret_path.resolve()
        secrets_files.append(secret_path)
        secrets.update(parse_dotenv(secret_path))

    def external(name: str) -> str | None:
        return os.environ.get(name) or secrets.get(name)

    human_pubkey = (
        bridge_raw.get("human_pubkey")
        or bridge_raw.get("owner_pubkey")
        or external("BUZZR_HUMAN_PUBKEY")
        or external("BUZZ_PUBLIC_KEY")
        or None
    )
    if human_pubkey:
        human_pubkey = str(human_pubkey).lower()
    if human_pubkey and not HEX64_RE.fullmatch(human_pubkey):
        raise ConfigError("bridge.human_pubkey must be 64 lowercase hexadecimal characters")

    bridge_public_key = (
        bridge_raw.get("bridge_public_key")
        or external("BUZZR_BRIDGE_PUBLIC_KEY")
        or None
    )
    if bridge_public_key:
        bridge_public_key = str(bridge_public_key).lower()
    if bridge_public_key and not HEX64_RE.fullmatch(bridge_public_key):
        raise ConfigError("bridge.bridge_public_key must be 64 lowercase hexadecimal characters")

    def resolve_config_path(raw_value: Any) -> Path | None:
        if not raw_value:
            return None
        resolved = Path(str(raw_value)).expanduser()
        if not resolved.is_absolute():
            resolved = path.parent / resolved
        return resolved.resolve()

    compose_file = resolve_config_path(bridge_raw.get("compose_file"))
    managed_secrets_file = resolve_config_path(bridge_raw.get("managed_secrets_file"))
    avatar_pack_path = resolve_config_path(bridge_raw.get("avatar_pack_path"))

    respond_to = str(bridge_raw.get("respond_to", "owner-only"))
    if respond_to not in {"owner-only", "allowlist", "anyone", "nobody"}:
        raise ConfigError("bridge.respond_to must be owner-only, allowlist, anyone, or nobody")
    channel_type = str(bridge_raw.get("channel_type", "stream"))
    if channel_type not in {"stream", "forum"}:
        raise ConfigError("bridge.channel_type must be stream or forum")
    visibility = str(bridge_raw.get("channel_visibility", "private"))
    if visibility not in {"open", "private"}:
        raise ConfigError("bridge.channel_visibility must be open or private")

    bridge = BridgeConfig(
        relay_url=str(
            external("BUZZR_RELAY_URL")
            or external("BUZZ_RELAY_URL")
            or bridge_raw.get("relay_url", "wss://buzz.nuts.cash")
        ),
        buzz_bin=str(bridge_raw.get("buzz_bin", "buzz")),
        herdr_bin=str(bridge_raw.get("herdr_bin", os.environ.get("HERDR_BIN_PATH", "herdr"))),
        nak_bin=str(bridge_raw.get("nak_bin", "nak")),
        secrets_files=tuple(secrets_files),
        managed_secrets_file=managed_secrets_file,
        bridge_private_key_env=str(
            bridge_raw.get(
                "bridge_private_key_env",
                bridge_raw.get("owner_private_key_env", "BUZZ_PRIVATE_KEY"),
            )
        ),
        bridge_auth_tag_env=(
            str(
                bridge_raw.get(
                    "bridge_auth_tag_env",
                    bridge_raw.get("owner_auth_tag_env"),
                )
            )
            if bridge_raw.get(
                "bridge_auth_tag_env",
                bridge_raw.get("owner_auth_tag_env"),
            )
            else None
        ),
        bridge_public_key=bridge_public_key,
        human_pubkey=human_pubkey,
        compose_file=compose_file,
        relay_service=str(bridge_raw.get("relay_service", "relay")),
        postgres_service=str(bridge_raw.get("postgres_service", "postgres")),
        postgres_user=str(bridge_raw.get("postgres_user", "buzz")),
        postgres_database=str(bridge_raw.get("postgres_database", "buzz")),
        include_spaces=_as_tuple(bridge_raw.get("include_spaces"), ("*",)),
        exclude_spaces=_as_tuple(bridge_raw.get("exclude_spaces"), ("~",)),
        channel_type=channel_type,
        channel_visibility=visibility,
        channel_description=str(
            bridge_raw.get("channel_description", "Mirrored from Herdr Space {space}.")
        ),
        sync_enabled=bool(bridge_raw.get("sync_enabled", False)),
        routing_enabled=bool(bridge_raw.get("routing_enabled", False)),
        archive_closed_spaces=bool(bridge_raw.get("archive_closed_spaces", False)),
        remove_departed_agents=bool(bridge_raw.get("remove_departed_agents", False)),
        respond_to=respond_to,
        respond_to_allowlist=_as_tuple(bridge_raw.get("respond_to_allowlist"), ()),
        poll_seconds=max(1.0, float(bridge_raw.get("poll_seconds", 5.0))),
        message_poll_seconds=max(1.0, float(bridge_raw.get("message_poll_seconds", 2.0))),
        auto_provision_agents=bool(bridge_raw.get("auto_provision_agents", False)),
        avatars_enabled=bool(bridge_raw.get("avatars_enabled", True)),
        avatar_pack=str(bridge_raw.get("avatar_pack", "bees-v1")),
        avatar_pack_path=avatar_pack_path,
    )

    identities_raw = raw.get("identities", {})
    if not isinstance(identities_raw, dict):
        raise ConfigError("[identities] must be a table")
    identities: dict[str, IdentityConfig] = {}
    alias_owner: dict[str, str] = {}
    for identity_id, value in identities_raw.items():
        if not isinstance(value, dict):
            raise ConfigError(f"[identities.{identity_id}] must be a table")
        normalized_id = normalize_name(identity_id)
        if not normalized_id or normalized_id != identity_id:
            raise ConfigError(f"identity id must be normalized lowercase kebab-case: {identity_id}")
        public_key = str(value.get("public_key", ""))
        if not HEX64_RE.fullmatch(public_key):
            raise ConfigError(f"identities.{identity_id}.public_key must be 64 lowercase hex")
        private_key_env = str(value.get("private_key_env", ""))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", private_key_env):
            raise ConfigError(f"identities.{identity_id}.private_key_env is invalid")
        auth_tag_env = value.get("auth_tag_env")
        identity = IdentityConfig(
            identity_id=identity_id,
            display_name=str(value.get("display_name", identity_id)),
            aliases=_as_tuple(value.get("aliases"), (identity_id,)),
            public_key=public_key,
            private_key_env=str(private_key_env),
            auth_tag_env=str(auth_tag_env) if auth_tag_env else None,
        )
        for alias in identity.normalized_aliases:
            previous = alias_owner.get(alias)
            if previous and previous != identity_id:
                raise ConfigError(f"identity alias {alias!r} belongs to both {previous} and {identity_id}")
            alias_owner[alias] = identity_id
        identities[identity_id] = identity

    return Config(bridge=bridge, identities=identities, secrets=secrets)
