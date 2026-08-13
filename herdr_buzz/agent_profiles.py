from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .config import Config
from .topology import Topology


# Agent profiles are replaceable events, but refreshing them occasionally makes
# recovery deterministic if relay event storage is restored independently from
# buzzr's local state.
AGENT_PROFILE_REFRESH_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class AgentProfileDeclaration:
    identity_id: str
    public_key: str
    content: dict[str, Any]

    @property
    def encoded_content(self) -> str:
        return json.dumps(self.content, separators=(",", ":"), sort_keys=True)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.encoded_content.encode("utf-8")).hexdigest()


def _directory_access(config: Config) -> tuple[str, list[str]]:
    """Project buzzr's author gate into Buzz Desktop's discovery contract.

    Desktop's relay-agent eligibility understands `allowlist` and `anyone`.
    It cannot resolve buzzr's locally assigned owner for `owner-only`, so the
    equivalent wire representation is an allowlist containing the human owner.
    An empty allowlist represents `nobody` without publishing an unknown mode.
    """

    mode = config.bridge.respond_to
    if mode == "anyone":
        return "anyone", []

    allowed: set[str] = set()
    if mode == "allowlist":
        allowed.update(value.lower() for value in config.bridge.respond_to_allowlist)
    if mode in {"owner-only", "allowlist"}:
        human_pubkey = config.human_public_key()
        if human_pubkey:
            allowed.add(human_pubkey.lower())
    return "allowlist", sorted(allowed)


def build_agent_profile_declarations(
    config: Config,
    topology: Topology,
    channel_state: Mapping[str, Any],
) -> list[AgentProfileDeclaration]:
    """Build one complete kind:10100 declaration per buzzr identity.

    An identity can appear in several Herdr Spaces, so its channel list must be
    aggregated before publishing the replaceable event. Configured identities
    that are not currently live are declared offline with no invocable channels,
    clearing any stale directory record left by a previous topology.
    """

    channel_pairs: dict[str, set[tuple[str, str]]] = {
        identity_id: set() for identity_id in config.identities
    }
    runtimes: dict[str, set[str]] = {identity_id: set() for identity_id in config.identities}
    active_identities: set[str] = set()

    for space in topology.spaces:
        mapping = channel_state.get(space.workspace_id, {})
        channel_id = mapping.get("channel_id") if isinstance(mapping, dict) else None
        channel_name = (
            str(mapping.get("name") or space.channel_name)
            if isinstance(mapping, dict)
            else space.channel_name
        )
        for agent in space.agents:
            identity_id = agent.identity_id
            if not identity_id or identity_id not in config.identities:
                continue
            active_identities.add(identity_id)
            runtime = agent.runtime.strip()
            if runtime:
                runtimes[identity_id].add(runtime)
            if isinstance(channel_id, str) and channel_id:
                channel_pairs[identity_id].add((channel_name, channel_id))

    respond_to, respond_to_allowlist = _directory_access(config)
    declarations: list[AgentProfileDeclaration] = []
    for identity_id, identity in sorted(config.identities.items()):
        pairs = sorted(channel_pairs[identity_id], key=lambda pair: (pair[0].casefold(), pair[1]))
        runtime_values = sorted(runtimes[identity_id])
        agent_type = runtime_values[0] if len(runtime_values) == 1 else "herdr"
        declarations.append(
            AgentProfileDeclaration(
                identity_id=identity_id,
                public_key=identity.public_key,
                content={
                    "name": identity.display_name,
                    "display_name": identity.display_name,
                    "agent_type": agent_type,
                    "channels": [name for name, _channel_id in pairs],
                    "channel_ids": [channel_id for _name, channel_id in pairs],
                    "capabilities": [],
                    "status": "online" if identity_id in active_identities else "offline",
                    "respond_to": respond_to,
                    "respond_to_allowlist": respond_to_allowlist,
                    # The bridge must be able to add its identities without the
                    # human signing every channel membership event.
                    "channel_add_policy": "anyone",
                },
            )
        )
    return declarations
