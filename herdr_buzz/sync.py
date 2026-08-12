from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .clients import BuzzClient, CommandError
from .config import Config
from .state import StateStore
from .topology import Topology


def _channel_id(channel: dict[str, Any]) -> str | None:
    for key in ("channel_id", "channelId", "id"):
        value = channel.get(key)
        if isinstance(value, str) and value:
            return value
    return None


@dataclass
class SyncReport:
    applied: bool
    actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def reconcile(
    config: Config,
    topology: Topology,
    store: StateStore,
    *,
    force_apply: bool = False,
) -> SyncReport:
    apply = force_apply or config.bridge.sync_enabled
    report = SyncReport(applied=apply, warnings=list(topology.warnings))
    state = store.load()
    signer_records = config.reader_credentials()
    bridge_key, bridge_auth = config.bridge_credentials()
    bridge_pubkey = config.bridge.bridge_public_key
    human_pubkey = config.human_public_key()
    if not signer_records:
        report.warnings.append("No Buzz credential is available; channel discovery was skipped")
        for space in topology.spaces:
            report.actions.append(f"would discover or create #{space.channel_name}")
        return report
    if apply and not bridge_key:
        raise CommandError(
            f"sync is enabled but {config.bridge.bridge_private_key_env} is unavailable; "
            "run `buzzr bootstrap` to create the operational bridge identity"
        )

    readers: list[tuple[str | None, BuzzClient]] = [
        (
            pubkey,
            BuzzClient(
                config.bridge.buzz_bin,
                config.bridge.relay_url,
                private_key,
                auth_tag,
            ),
        )
        for pubkey, private_key, auth_tag in signer_records
    ]
    channels_by_id: dict[str, dict[str, Any]] = {}
    channel_readers: dict[str, BuzzClient] = {}
    for _pubkey, client in readers:
        try:
            visible = client.list_channels()
        except CommandError as exc:
            report.warnings.append(f"one Buzz identity could not list channels: {exc}")
            continue
        for channel in visible:
            channel_id = _channel_id(channel)
            if channel_id:
                channels_by_id.setdefault(channel_id, channel)
                channel_readers.setdefault(channel_id, client)

    by_name: dict[str, list[dict[str, Any]]] = {}
    for channel in channels_by_id.values():
        name = str(channel.get("name", "")).casefold()
        if name:
            by_name.setdefault(name, []).append(channel)

    writer = (
        BuzzClient(
            config.bridge.buzz_bin,
            config.bridge.relay_url,
            bridge_key,
            bridge_auth,
        )
        if bridge_key
        else None
    )
    active_workspace_ids = {space.workspace_id for space in topology.spaces}

    for space in topology.spaces:
        mapping = state["channels"].get(space.workspace_id, {})
        channel_id = mapping.get("channel_id") if isinstance(mapping, dict) else None
        exact = by_name.get(space.channel_name.casefold(), [])
        if not channel_id:
            if len(exact) == 1:
                channel_id = _channel_id(exact[0])
                if channel_id:
                    report.actions.append(f"adopted existing #{space.channel_name} ({channel_id})")
            elif len(exact) > 1:
                report.warnings.append(
                    f"multiple Buzz channels exactly match {space.channel_name!r}; refusing to guess"
                )
                continue

        description = config.bridge.channel_description.format(
            space=space.workspace_label,
            workspace_id=space.workspace_id,
        )
        if not channel_id:
            report.actions.append(f"{'create' if apply else 'would create'} #{space.channel_name}")
            if apply and writer:
                created = writer.create_channel(
                    space.channel_name,
                    config.bridge.channel_type,
                    config.bridge.channel_visibility,
                    description,
                )
                channel_id = _channel_id(created)
                if not channel_id:
                    raise CommandError(f"Buzz did not return a channel id for {space.channel_name}")
                channel_readers[channel_id] = writer

        if not channel_id:
            continue
        state["channels"][space.workspace_id] = {
            "channel_id": channel_id,
            "name": space.channel_name,
            "space_label": space.workspace_label,
        }

        channel_reader = channel_readers.get(channel_id) or writer
        if not channel_reader:
            report.warnings.append(f"cannot inspect members of #{space.channel_name}")
            continue
        try:
            current_members = channel_reader.members(channel_id)
        except CommandError as exc:
            report.warnings.append(f"cannot inspect members of #{space.channel_name}: {exc}")
            continue
        current_roles = {
            str(member.get("pubkey", "")).lower(): str(member.get("role", "member"))
            for member in current_members
            if member.get("pubkey")
        }

        # An adopted private channel may predate buzzr. Any existing member may
        # invite the bridge as a normal member; after that the bridge can add
        # non-elevated bot identities without the human's private key.
        if bridge_pubkey and bridge_pubkey not in current_roles:
            report.actions.append(
                f"{'add' if apply else 'would add'} buzzr bridge to #{space.channel_name}"
            )
            if apply:
                inviter: BuzzClient | None = None
                for signer_pubkey, candidate in readers:
                    if signer_pubkey and signer_pubkey in current_roles:
                        inviter = candidate
                        break
                # A newly-created channel is already owned by the bridge even if
                # a stale read omitted it.
                if inviter is None and writer and channel_id not in channels_by_id:
                    inviter = writer
                if inviter is None:
                    report.warnings.append(
                        f"no configured member can invite the bridge to #{space.channel_name}"
                    )
                    continue
                inviter.add_member(channel_id, bridge_pubkey, role="member")
                current_roles[bridge_pubkey] = "member"

        if human_pubkey and human_pubkey not in current_roles:
            report.actions.append(
                f"{'add' if apply else 'would add'} human owner to #{space.channel_name}"
            )
            if apply and writer:
                bridge_role = current_roles.get(bridge_pubkey or "")
                if bridge_role not in {"owner", "admin"}:
                    report.warnings.append(
                        f"buzzr is not elevated in adopted #{space.channel_name}; "
                        "it cannot grant human ownership"
                    )
                else:
                    writer.add_member(channel_id, human_pubkey, role="owner")
                    current_roles[human_pubkey] = "owner"

        for pubkey in space.member_pubkeys:
            if pubkey in current_roles:
                continue
            identity_names = sorted(
                {
                    agent.identity_id
                    for agent in space.agents
                    if agent.public_key == pubkey and agent.identity_id
                }
            )
            label = ", ".join(identity_names) or pubkey[:12]
            report.actions.append(
                f"{'add' if apply else 'would add'} {label} to #{space.channel_name}"
            )
            if apply and writer:
                writer.add_member(channel_id, pubkey, role="bot")

    if config.bridge.archive_closed_spaces:
        for workspace_id, mapping in list(state["channels"].items()):
            if workspace_id in active_workspace_ids or not isinstance(mapping, dict):
                continue
            channel_id = mapping.get("channel_id")
            name = mapping.get("name", workspace_id)
            if channel_id:
                report.actions.append(f"{'archive' if apply else 'would archive'} #{name}")
                if apply and writer:
                    writer.archive_channel(channel_id)

    state["last_reconcile_at"] = int(time.time())
    state["last_error"] = None
    store.save(state)
    return report
