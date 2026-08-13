from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import CommandError, LocalBuzzAdmin, NostrTools
from .config import (
    Config,
    ConfigError,
    IdentityConfig,
    append_identities,
    load_config,
    normalize_name,
    update_bridge_settings,
    update_dotenv,
)
from .topology import AgentBinding, Topology, build_topology


@dataclass
class ProvisionReport:
    bridge_created: bool = False
    identities_created: list[str] = field(default_factory=list)
    relay_members_added: int = 0
    ownership_bound: int = 0


def _private_env_name(identity_id: str) -> str:
    token = re.sub(r"[^A-Z0-9]+", "_", identity_id.upper()).strip("_") or "AGENT"
    return f"BUZZR_AGENT_{token}_PRIVATE_KEY"


def _aliases(binding: AgentBinding) -> list[str]:
    values = [binding.display_label]
    if binding.agent_name:
        values.append(binding.agent_name)
    if binding.tab_label.strip() and not binding.tab_label.strip().isdigit():
        values.append(binding.tab_label)
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = normalize_name(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(value)
    return result


def _admin(config: Config) -> LocalBuzzAdmin:
    compose_file = config.bridge.compose_file
    if not compose_file:
        raise ConfigError("bridge.compose_file is required for local automatic provisioning")
    if not compose_file.exists():
        raise ConfigError(f"Buzz Compose file does not exist: {compose_file}")
    return LocalBuzzAdmin(
        compose_file=compose_file,
        relay_service=config.bridge.relay_service,
        postgres_service=config.bridge.postgres_service,
        postgres_user=config.bridge.postgres_user,
        postgres_database=config.bridge.postgres_database,
    )


def _managed_secrets(config: Config) -> Path:
    path = config.bridge.managed_secrets_file
    if not path:
        raise ConfigError("bridge.managed_secrets_file is required for generated identities")
    return path


def ensure_bridge_identity(config_path: Path, config: Config) -> tuple[Config, bool]:
    """Create the non-human operational identity once and persist it privately."""
    tools = NostrTools(config.bridge.nak_bin)
    private_key, _auth = config.bridge_credentials()
    public_key = config.bridge.bridge_public_key
    created = False

    if private_key:
        derived = tools.public_key(private_key)
        if public_key and derived != public_key:
            raise ConfigError("configured bridge_public_key does not match the bridge private key")
        if not public_key:
            public_key = derived
            update_bridge_settings(config_path, {"bridge_public_key": public_key})
    elif public_key:
        raise ConfigError(
            f"{config.bridge.bridge_private_key_env} is missing but bridge_public_key is configured"
        )
    else:
        private_key, public_key = tools.generate_keypair()
        update_dotenv(
            _managed_secrets(config),
            {config.bridge.bridge_private_key_env: private_key},
        )
        update_bridge_settings(config_path, {"bridge_public_key": public_key})
        created = True

    return load_config(config_path), created


def ensure_agent_identities(
    config_path: Path,
    config: Config,
    snapshot: dict[str, Any],
) -> tuple[Config, Topology, list[IdentityConfig]]:
    """Create one stable Buzz identity for each currently unmapped agent label."""
    topology = build_topology(snapshot, config)
    grouped: dict[str, list[AgentBinding]] = {}
    for binding in topology.agents:
        if binding.identity_id:
            continue
        identity_id = normalize_name(binding.display_label)
        if not identity_id:
            identity_id = normalize_name(f"{binding.runtime}-{binding.pane_id}")
        if not identity_id:
            raise ConfigError(f"cannot derive an identity id for pane {binding.pane_id}")
        grouped.setdefault(identity_id, []).append(binding)

    if not grouped:
        return config, topology, []

    tools = NostrTools(config.bridge.nak_bin)
    identities: list[IdentityConfig] = []
    secrets: dict[str, str] = {}
    for identity_id, bindings in sorted(grouped.items()):
        if identity_id in config.identities:
            # Defensive: this normally cannot happen because the identity id is
            # itself an alias and build_topology would already have matched it.
            continue
        private_key, public_key = tools.generate_keypair()
        env_name = _private_env_name(identity_id)
        alias_values: list[str] = []
        seen: set[str] = set()
        for binding in bindings:
            for alias in _aliases(binding):
                normalized = normalize_name(alias)
                if normalized not in seen:
                    seen.add(normalized)
                    alias_values.append(alias)
        identities.append(
            IdentityConfig(
                identity_id=identity_id,
                display_name=bindings[0].display_label,
                aliases=tuple(alias_values or [identity_id]),
                public_key=public_key,
                private_key_env=env_name,
            )
        )
        secrets[env_name] = private_key

    if identities:
        update_dotenv(_managed_secrets(config), secrets)
        append_identities(config_path, identities)
        config = load_config(config_path)
        topology = build_topology(snapshot, config)
    return config, topology, identities


def provision_local(
    config_path: Path,
    snapshot: dict[str, Any],
) -> tuple[Config, Topology, ProvisionReport]:
    """Fully provision bridge/agents in a locally administered Buzz relay."""
    config = load_config(config_path)
    human_pubkey = config.human_public_key()
    if not human_pubkey:
        raise ConfigError("bridge.human_pubkey is required")
    config, bridge_created = ensure_bridge_identity(config_path, config)
    config, topology, created_identities = ensure_agent_identities(
        config_path, config, snapshot
    )

    bridge_public_key = config.bridge.bridge_public_key
    bridge_private_key, _bridge_auth = config.bridge_credentials()
    if not bridge_public_key or not bridge_private_key:
        raise ConfigError("bridge identity provisioning did not produce a complete keypair")

    admin = _admin(config)
    current_relay_members = admin.relay_member_pubkeys()
    desired_pubkeys = [bridge_public_key]
    desired_pubkeys.extend(identity.public_key for identity in config.identities.values())
    added = 0
    for pubkey in sorted(set(desired_pubkeys)):
        if pubkey not in current_relay_members:
            admin.add_relay_member(pubkey)
            added += 1

    # This trusted local write is the missing ownership link: it never requires
    # the human's secret key, and refuses to overwrite another existing owner.
    admin.assign_agent_owner(human_pubkey, desired_pubkeys)

    report = ProvisionReport(
        bridge_created=bridge_created,
        identities_created=[identity.identity_id for identity in created_identities],
        relay_members_added=added,
        ownership_bound=len(set(desired_pubkeys)),
    )
    return config, topology, report
