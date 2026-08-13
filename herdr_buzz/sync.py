from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .agent_profiles import AGENT_PROFILE_REFRESH_SECONDS, build_agent_profile_declarations
from .avatars import AvatarPackError, build_avatar, load_avatar_pack
from .clients import BuzzClient, CommandError, NostrTools
from .config import Config
from .state import StateStore, runtime_directory
from .topology import Topology


IDENTITY_PROFILE_REFRESH_SECONDS = 24 * 60 * 60


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


@dataclass(frozen=True)
class _ManagedProfile:
    cache_id: str
    public_key: str
    identity_id: str | None
    name: str
    about: str


def _managed_profiles(config: Config) -> list[_ManagedProfile]:
    profiles: list[_ManagedProfile] = []
    if config.bridge.bridge_public_key:
        profiles.append(
            _ManagedProfile(
                cache_id="@bridge",
                public_key=config.bridge.bridge_public_key,
                identity_id=None,
                name="buzzr",
                about="Herdr ↔ Buzz bridge managed by the buzzr plugin.",
            )
        )
    profiles.extend(
        _ManagedProfile(
            cache_id=identity.identity_id,
            public_key=identity.public_key,
            identity_id=identity.identity_id,
            name=identity.display_name,
            about=f"Herdr agent identity managed by buzzr ({identity.identity_id}).",
        )
        for identity in sorted(config.identities.values(), key=lambda item: item.identity_id)
    )
    return profiles


def _profile_credentials(
    config: Config,
    profile: _ManagedProfile,
) -> tuple[str | None, str | None]:
    if profile.identity_id is None:
        return config.bridge_credentials()
    return config.identity_credentials(profile.identity_id)


def _profile_fingerprint(
    profile: _ManagedProfile,
    *,
    relay_url: str,
    pack_id: str | None,
    avatar_sha256: str | None,
) -> str:
    encoded = json.dumps(
        {
            "public_key": profile.public_key,
            "relay_url": relay_url,
            "name": profile.name,
            "about": profile.about,
            "avatar_pack": pack_id,
            "avatar_sha256": avatar_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _picture_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return value


def _sync_identity_profiles(
    config: Config,
    state: dict[str, Any],
    report: SyncReport,
    *,
    apply: bool,
    now: int,
    avatar_output_dir: Path | None = None,
) -> None:
    """Upload stable avatars and publish kind:0 profiles for managed identities."""

    cache = state.setdefault("identity_profiles", {})
    if not isinstance(cache, dict):
        cache = {}
        state["identity_profiles"] = cache
    uploads = state.setdefault("avatar_uploads", {})
    if not isinstance(uploads, dict):
        uploads = {}
        state["avatar_uploads"] = uploads

    pack = None
    if config.bridge.avatars_enabled:
        try:
            pack = load_avatar_pack(
                config.bridge.avatar_pack,
                config.bridge.avatar_pack_path,
            )
        except AvatarPackError as exc:
            report.warnings.append(f"managed identity profiles were skipped: {exc}")
            return

    profiles = _managed_profiles(config)
    nak: NostrTools | None = None
    reserved_avatar_ids: set[str] = set()
    assets_by_id = (
        {asset.asset_id: asset for asset in pack.assets}
        if pack and not pack.layered
        else {}
    )
    preserved_avatars: dict[str, Any] = {}
    if pack and not pack.layered:
        # Reserve every valid existing assignment before placing newcomers, so
        # a newly-added identity that sorts earlier cannot steal an old avatar.
        for profile in profiles:
            cached = cache.get(profile.cache_id, {})
            cached_avatar_id = (
                cached.get("avatar_id") if isinstance(cached, dict) else None
            )
            if (
                isinstance(cached_avatar_id, str)
                and cached_avatar_id in assets_by_id
                and cached.get("avatar_pack") == pack.pack_id
                and (
                    cached_avatar_id not in reserved_avatar_ids
                    or len(reserved_avatar_ids) >= len(pack.assets)
                )
            ):
                preserved_avatars[profile.cache_id] = assets_by_id[cached_avatar_id]
                reserved_avatar_ids.add(cached_avatar_id)

    for profile in profiles:
        cached = cache.get(profile.cache_id, {})
        avatar = None
        if pack:
            if pack.layered:
                render_directory = (
                    avatar_output_dir or runtime_directory() / "avatars"
                    if apply
                    else None
                )
                try:
                    avatar = build_avatar(
                        pack,
                        profile.public_key,
                        output_directory=render_directory,
                    )
                except AvatarPackError as exc:
                    report.warnings.append(
                        f"cannot compose avatar for {profile.name}: {exc}"
                    )
                    continue
            else:
                avatar = preserved_avatars.get(profile.cache_id)
                if avatar is None:
                    avatar = build_avatar(
                        pack,
                        profile.public_key,
                        excluded_ids=reserved_avatar_ids,
                    )
                reserved_avatar_ids.add(avatar.asset_id)
        fingerprint = _profile_fingerprint(
            profile,
            relay_url=config.bridge.relay_url,
            pack_id=pack.pack_id if pack else None,
            avatar_sha256=avatar.sha256 if avatar else None,
        )
        published_at = cached.get("published_at") if isinstance(cached, dict) else None
        unchanged = (
            isinstance(cached, dict)
            and cached.get("public_key") == profile.public_key
            and cached.get("fingerprint") == fingerprint
        )
        fresh = (
            isinstance(published_at, int)
            and 0 <= now - published_at < IDENTITY_PROFILE_REFRESH_SECONDS
        )
        if unchanged and fresh:
            continue

        avatar_label = f" with {avatar.asset_id}" if avatar else ""
        report.actions.append(
            f"{'publish' if apply else 'would publish'} profile for "
            f"{profile.name}{avatar_label}"
        )
        if not apply:
            continue

        private_key, auth_tag = _profile_credentials(config, profile)
        if not private_key:
            report.warnings.append(
                f"cannot publish profile for {profile.name}: its private key is unavailable"
            )
            continue

        picture: str | None = None
        if avatar:
            cached_upload = uploads.get(avatar.sha256, {})
            if (
                isinstance(cached_upload, dict)
                and cached_upload.get("relay_url") == config.bridge.relay_url
            ):
                picture = _picture_url(cached_upload.get("url"))
            if picture is None:
                uploader = BuzzClient(
                    config.bridge.buzz_bin,
                    config.bridge.relay_url,
                    private_key,
                    auth_tag,
                )
                try:
                    descriptor = uploader.upload_file(avatar.path)
                except CommandError as exc:
                    report.warnings.append(
                        f"cannot upload avatar for {profile.name}: {exc}"
                    )
                    continue
                picture = _picture_url(descriptor.get("url"))
                if picture is None:
                    report.warnings.append(
                        f"cannot upload avatar for {profile.name}: "
                        "Buzz returned no public HTTP URL"
                    )
                    continue
                uploads[avatar.sha256] = {
                    "asset_id": avatar.asset_id,
                    "traits": dict(avatar.traits),
                    "relay_url": config.bridge.relay_url,
                    "url": picture,
                    "uploaded_at": now,
                }

        if nak is None:
            nak = NostrTools(config.bridge.nak_bin)
        try:
            nak.publish_profile(
                config.bridge.relay_url,
                private_key,
                name=profile.name,
                about=profile.about,
                picture=picture,
            )
        except CommandError as exc:
            report.warnings.append(f"cannot publish profile for {profile.name}: {exc}")
            continue
        cache[profile.cache_id] = {
            "public_key": profile.public_key,
            "fingerprint": fingerprint,
            "published_at": now,
            "avatar_id": avatar.asset_id if avatar else None,
            "avatar_pack": pack.pack_id if pack else None,
            "avatar_sha256": avatar.sha256 if avatar else None,
            "avatar_traits": dict(avatar.traits) if avatar else {},
            "picture_url": picture,
        }


def _sync_agent_profiles(
    config: Config,
    topology: Topology,
    state: dict[str, Any],
    report: SyncReport,
    *,
    apply: bool,
    now: int,
) -> None:
    cache = state.setdefault("agent_profiles", {})
    if not isinstance(cache, dict):
        cache = {}
        state["agent_profiles"] = cache

    nak: NostrTools | None = None
    declarations = build_agent_profile_declarations(config, topology, state["channels"])
    for declaration in declarations:
        cached = cache.get(declaration.identity_id, {})
        published_at = cached.get("published_at") if isinstance(cached, dict) else None
        unchanged = (
            isinstance(cached, dict)
            and cached.get("public_key") == declaration.public_key
            and cached.get("fingerprint") == declaration.fingerprint
        )
        fresh = (
            isinstance(published_at, int)
            and 0 <= now - published_at < AGENT_PROFILE_REFRESH_SECONDS
        )
        if unchanged and fresh:
            continue

        channel_count = len(declaration.content["channel_ids"])
        verb = "publish" if apply else "would publish"
        report.actions.append(
            f"{verb} agent declaration for {declaration.identity_id} "
            f"({channel_count} channel{'s' if channel_count != 1 else ''})"
        )
        if not apply:
            continue

        private_key, _auth_tag = config.identity_credentials(declaration.identity_id)
        if not private_key:
            report.warnings.append(
                f"cannot publish agent declaration for {declaration.identity_id}: "
                "its private key is unavailable"
            )
            continue
        if nak is None:
            nak = NostrTools(config.bridge.nak_bin)
        try:
            nak.publish_agent_profile(
                config.bridge.relay_url,
                private_key,
                declaration.content,
            )
        except CommandError as exc:
            report.warnings.append(
                f"cannot publish agent declaration for {declaration.identity_id}: {exc}"
            )
            continue
        cache[declaration.identity_id] = {
            "public_key": declaration.public_key,
            "fingerprint": declaration.fingerprint,
            "published_at": now,
            "channel_ids": list(declaration.content["channel_ids"]),
        }


def _reconcile_unlocked(
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

    now = int(time.time())
    _sync_identity_profiles(
        config,
        state,
        report,
        apply=apply,
        now=now,
        avatar_output_dir=store.directory / "avatars",
    )
    _sync_agent_profiles(
        config,
        topology,
        state,
        report,
        apply=apply,
        now=now,
    )

    state["last_reconcile_at"] = int(time.time())
    state["last_error"] = None
    store.save(state)
    return report


def reconcile(
    config: Config,
    topology: Topology,
    store: StateStore,
    *,
    force_apply: bool = False,
) -> SyncReport:
    """Reconcile while preventing daemon/actions from overwriting newer state."""

    with store.locked():
        return _reconcile_unlocked(
            config,
            topology,
            store,
            force_apply=force_apply,
        )


def refresh_profiles(
    config: Config,
    topology: Topology,
    store: StateStore,
    *,
    reupload: bool = False,
) -> SyncReport:
    """Refresh managed Nostr profiles without an unrelated channel scan."""

    report = SyncReport(applied=True, warnings=list(topology.warnings))
    with store.locked():
        state = store.load()
        profiles = state.get("identity_profiles", {})
        if isinstance(profiles, dict):
            for cached in profiles.values():
                if isinstance(cached, dict):
                    cached.pop("published_at", None)
        else:
            state["identity_profiles"] = {}
        if reupload:
            state["avatar_uploads"] = {}

        now = int(time.time())
        _sync_identity_profiles(
            config,
            state,
            report,
            apply=True,
            now=now,
            avatar_output_dir=store.directory / "avatars",
        )
        _sync_agent_profiles(
            config,
            topology,
            state,
            report,
            apply=True,
            now=now,
        )
        state["last_error"] = None
        store.save(state)
    return report
