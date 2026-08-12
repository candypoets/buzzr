from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from .config import Config, normalize_name


def channel_slug(label: str) -> str:
    slug = normalize_name(label)
    if not slug:
        slug = "herdr-space"
    return slug[:64].rstrip("-")


def _meaningful_tab_label(label: str) -> bool:
    normalized = label.strip()
    return bool(normalized and not normalized.isdigit())


@dataclass(frozen=True)
class AgentBinding:
    workspace_id: str
    workspace_label: str
    channel_name: str
    pane_id: str
    terminal_id: str
    tab_id: str
    tab_label: str
    runtime: str
    status: str
    agent_name: str | None
    display_label: str
    identity_id: str | None
    public_key: str | None


@dataclass
class SpaceBinding:
    workspace_id: str
    workspace_label: str
    channel_name: str
    number: int
    agents: list[AgentBinding] = field(default_factory=list)

    @property
    def member_pubkeys(self) -> tuple[str, ...]:
        return tuple(sorted({agent.public_key for agent in self.agents if agent.public_key}))


@dataclass
class Topology:
    spaces: list[SpaceBinding]
    warnings: list[str] = field(default_factory=list)

    @property
    def agents(self) -> list[AgentBinding]:
        return [agent for space in self.spaces for agent in space.agents]


def _included(label: str, config: Config) -> bool:
    included = any(fnmatch.fnmatchcase(label, pattern) for pattern in config.bridge.include_spaces)
    excluded = any(fnmatch.fnmatchcase(label, pattern) for pattern in config.bridge.exclude_spaces)
    return included and not excluded


def _identity_alias_map(config: Config) -> dict[str, str]:
    result: dict[str, str] = {}
    for identity in config.identities.values():
        for alias in identity.normalized_aliases:
            result[alias] = identity.identity_id
    return result


def build_topology(snapshot: dict[str, Any], config: Config) -> Topology:
    workspaces = snapshot.get("workspaces", [])
    tabs = {tab.get("tab_id", ""): tab for tab in snapshot.get("tabs", [])}
    agents = snapshot.get("agents", [])
    alias_map = _identity_alias_map(config)
    warnings: list[str] = []
    spaces: list[SpaceBinding] = []
    channel_owners: dict[str, str] = {}

    for workspace in sorted(workspaces, key=lambda item: item.get("number", 0)):
        workspace_id = str(workspace.get("workspace_id", ""))
        label = str(workspace.get("label", workspace_id))
        if not workspace_id or not _included(label, config):
            continue
        channel_name = channel_slug(label)
        previous = channel_owners.get(channel_name)
        if previous and previous != workspace_id:
            warnings.append(
                f"Spaces {previous} and {workspace_id} both normalize to Buzz channel {channel_name!r}"
            )
        channel_owners[channel_name] = workspace_id
        space = SpaceBinding(
            workspace_id=workspace_id,
            workspace_label=label,
            channel_name=channel_name,
            number=int(workspace.get("number", 0)),
        )

        identity_seen: dict[str, str] = {}
        for agent in agents:
            if agent.get("workspace_id") != workspace_id:
                continue
            tab_id = str(agent.get("tab_id", ""))
            tab_label = str(tabs.get(tab_id, {}).get("label", ""))
            agent_name = str(agent["name"]) if agent.get("name") else None
            runtime = str(agent.get("agent", "agent"))
            pane_id = str(agent.get("pane_id", ""))
            terminal_id = str(agent.get("terminal_id", pane_id))
            display_label = (
                agent_name
                or (tab_label if _meaningful_tab_label(tab_label) else None)
                or f"{runtime}-{re.sub(r'[^A-Za-z0-9]+', '', pane_id.split(':')[-1])}"
            )

            identity_id = None
            candidates = [agent_name, tab_label, display_label]
            for candidate in candidates:
                normalized = normalize_name(candidate or "")
                if normalized in alias_map:
                    identity_id = alias_map[normalized]
                    break
            identity = config.identities.get(identity_id) if identity_id else None
            if identity_id:
                previous_pane = identity_seen.get(identity_id)
                if previous_pane and previous_pane != pane_id:
                    warnings.append(
                        f"Space {label!r} has multiple panes for identity {identity_id!r}: "
                        f"{previous_pane}, {pane_id}; routing will use the first ready pane"
                    )
                identity_seen.setdefault(identity_id, pane_id)
            else:
                warnings.append(
                    f"Unmapped agent {display_label!r} in Space {label!r} ({pane_id}); "
                    "it will be visible in the plan but cannot join or receive Buzz messages"
                )

            space.agents.append(
                AgentBinding(
                    workspace_id=workspace_id,
                    workspace_label=label,
                    channel_name=channel_name,
                    pane_id=pane_id,
                    terminal_id=terminal_id,
                    tab_id=tab_id,
                    tab_label=tab_label,
                    runtime=runtime,
                    status=str(agent.get("agent_status", "unknown")),
                    agent_name=agent_name,
                    display_label=display_label,
                    identity_id=identity_id,
                    public_key=identity.public_key if identity else None,
                )
            )
        spaces.append(space)

    return Topology(spaces=spaces, warnings=warnings)


def mentioned_pubkeys(event: dict[str, Any]) -> set[str]:
    mentions: set[str] = set()
    for tag in event.get("tags", []):
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p" and isinstance(tag[1], str):
            mentions.add(tag[1].lower())
    return mentions
