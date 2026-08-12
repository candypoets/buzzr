from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .clients import BuzzClient, CommandError, HerdrClient
from .config import (
    Config,
    ConfigError,
    load_config,
    update_bridge_settings,
    update_dotenv,
)
from .provisioning import provision_local
from .service import BridgeService, queue_reply
from .state import StateStore
from .sync import SyncReport, reconcile
from .topology import Topology, build_topology


PLUGIN_ROOT = Path(os.environ.get("HERDR_PLUGIN_ROOT", Path(__file__).resolve().parents[1]))


def config_path(argument: str | None = None) -> Path:
    if argument:
        return Path(argument).expanduser()
    explicit = os.environ.get("BUZZR_CONFIG") or os.environ.get("HERDR_BUZZ_CONFIG")
    if explicit:
        return Path(explicit).expanduser()
    config_dir = os.environ.get("HERDR_PLUGIN_CONFIG_DIR")
    if config_dir:
        return Path(config_dir) / "config.toml"
    return PLUGIN_ROOT / "config.toml"


def state_directory(argument: str | None = None) -> Path:
    if argument:
        return Path(argument).expanduser()
    explicit = os.environ.get("BUZZR_STATE_DIR") or os.environ.get("HERDR_BUZZ_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    state_dir = os.environ.get("HERDR_PLUGIN_STATE_DIR")
    if state_dir:
        return Path(state_dir)
    return PLUGIN_ROOT / ".state"


def _load(args: argparse.Namespace) -> tuple[Config, StateStore, Topology]:
    config = load_config(config_path(args.config))
    store = StateStore(state_directory(args.state_dir))
    snapshot = HerdrClient(config.bridge.herdr_bin).snapshot()
    return config, store, build_topology(snapshot, config)


def _ensure_config(destination: Path) -> bool:
    """Create the generic safe template. Return True when it was created."""
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists():
        return False
    shutil.copyfile(PLUGIN_ROOT / "config.example.toml", destination)
    os.chmod(destination, 0o600)
    return True


def _credential_source(config: Config) -> str:
    if config.bridge.secrets_files:
        return ", ".join(str(path) for path in config.bridge.secrets_files)
    return "inherited environment"


def _print_credential_summary(config: Config) -> None:
    private_key, auth_tag = config.bridge_credentials()
    print(f"Credential source: {_credential_source(config)}")
    print(
        f"Bridge signing key ({config.bridge.bridge_private_key_env}): "
        f"{'available' if private_key else 'MISSING'}"
    )
    if config.bridge.bridge_auth_tag_env:
        print(
            f"Delegation ({config.bridge.bridge_auth_tag_env}): "
            f"{'available' if auth_tag else 'not set'}"
        )
    print(
        "Human controller pubkey: "
        f"{'available' if config.human_public_key() else 'MISSING'}"
    )


def _apply_configuration(
    destination: Path,
    *,
    relay: str | None,
    environment: bool,
    secrets_file: str | None,
    private_key_env: str | None,
    auth_tag_env: str | None,
    owner_pubkey: str | None,
) -> Config:
    _ensure_config(destination)
    updates: dict[str, str | bool | None] = {}
    if relay:
        updates["relay_url"] = relay
    if environment:
        updates["secrets_file"] = None
        updates["secrets_files"] = None
    elif secrets_file:
        resolved = Path(secrets_file).expanduser().resolve()
        updates["secrets_files"] = [str(resolved)]
        updates["secrets_file"] = None
    if private_key_env:
        updates["bridge_private_key_env"] = private_key_env
    if auth_tag_env:
        updates["bridge_auth_tag_env"] = auth_tag_env
    if owner_pubkey:
        updates["human_pubkey"] = owner_pubkey.lower()
    if updates:
        update_bridge_settings(destination, updates)
    return load_config(destination)


def _topology_dict(topology: Topology) -> dict[str, Any]:
    return {
        "spaces": [
            {
                "workspace_id": space.workspace_id,
                "space": space.workspace_label,
                "channel": space.channel_name,
                "agents": [
                    {
                        "label": agent.display_label,
                        "identity": agent.identity_id,
                        "runtime": agent.runtime,
                        "status": agent.status,
                        "pane_id": agent.pane_id,
                    }
                    for agent in space.agents
                ],
            }
            for space in topology.spaces
        ],
        "warnings": topology.warnings,
    }


def _print_plan(topology: Topology) -> None:
    print(f"Herdr → Buzz: {len(topology.spaces)} Spaces, {len(topology.agents)} agents")
    for space in topology.spaces:
        print(f"\n#{space.channel_name}  ({space.workspace_id}, {space.workspace_label})")
        if not space.agents:
            print("  · no agents")
            continue
        for agent in space.agents:
            identity = agent.identity_id or "UNMAPPED"
            print(
                f"  · {agent.display_label} → {identity} "
                f"[{agent.runtime}/{agent.status}] {agent.pane_id}"
            )
    if topology.warnings:
        print("\nWarnings:")
        for warning in topology.warnings:
            print(f"  ! {warning}")


def _print_report(report: SyncReport) -> None:
    print("mode: APPLY" if report.applied else "mode: PREVIEW")
    if report.actions:
        for action in report.actions:
            print(f"  · {action}")
    else:
        print("  · already reconciled")
    for warning in report.warnings:
        print(f"  ! {warning}")


def cmd_init(args: argparse.Namespace) -> int:
    destination = config_path(args.config)
    if destination.exists() and not args.force:
        print(f"configuration already exists: {destination}", file=sys.stderr)
        return 1
    if args.force and destination.exists():
        destination.unlink()
    _ensure_config(destination)
    print(destination)
    return 0


def cmd_configure(args: argparse.Namespace) -> int:
    destination = config_path(args.config)
    config = _apply_configuration(
        destination,
        relay=args.relay,
        environment=args.environment,
        secrets_file=args.secrets_file,
        private_key_env=args.private_key_env,
        auth_tag_env=args.auth_tag_env,
        owner_pubkey=args.owner_pubkey,
    )
    print(f"Configured: {destination}")
    print(f"Relay: {config.bridge.relay_url}")
    _print_credential_summary(config)
    print("Channel writes and message routing were not enabled.")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    """Make the local plugin operational without ever asking for a human secret."""
    destination = config_path(args.config)
    _ensure_config(destination)

    try:
        current = load_config(destination)
    except ConfigError:
        current = None

    human_pubkey = args.human_pubkey or (
        current.human_public_key() if current else None
    )
    if not human_pubkey:
        raise ConfigError("--human-pubkey is required on first bootstrap")

    managed = Path(
        args.managed_secrets_file or destination.parent / "secrets.env"
    ).expanduser().resolve()
    # Create the destination before pointing config.toml at it. Empty is valid.
    update_dotenv(managed, {})

    secret_paths: list[str] = []
    if current:
        for path in current.bridge.secrets_files:
            resolved = str(path.resolve())
            if resolved != str(managed) and resolved not in secret_paths:
                secret_paths.append(resolved)
    if args.agent_secrets_file:
        agent_secrets = str(Path(args.agent_secrets_file).expanduser().resolve())
        if agent_secrets != str(managed) and agent_secrets not in secret_paths:
            secret_paths.append(agent_secrets)
    # The managed file is last, so generated values win over legacy variables.
    secret_paths.append(str(managed))

    compose_file = Path(
        args.compose_file
        or (current.bridge.compose_file if current and current.bridge.compose_file else "~/buzz/docker-compose.yml")
    ).expanduser().resolve()
    updates: dict[str, Any | None] = {
        "human_pubkey": human_pubkey.lower(),
        "relay_url": args.relay or (current.bridge.relay_url if current else "wss://buzz.nuts.cash"),
        "compose_file": str(compose_file),
        "managed_secrets_file": str(managed),
        "secrets_files": secret_paths,
        "secrets_file": None,
        "bridge_private_key_env": "BUZZR_BRIDGE_PRIVATE_KEY",
        "bridge_auth_tag_env": None,
        "owner_private_key_env": None,
        "owner_auth_tag_env": None,
        "owner_pubkey": None,
        # Enable only after provisioning and the first reconcile both succeed.
        "sync_enabled": False,
        "routing_enabled": False,
        "auto_provision_agents": False,
    }
    if args.buzz_bin:
        updates["buzz_bin"] = str(Path(args.buzz_bin).expanduser().resolve())
    if args.nak_bin:
        updates["nak_bin"] = args.nak_bin
    update_bridge_settings(destination, updates)

    config = load_config(destination)
    snapshot = HerdrClient(config.bridge.herdr_bin).snapshot()
    config, topology, provision = provision_local(destination, snapshot)
    store = StateStore(state_directory(args.state_dir))
    report = reconcile(config, topology, store, force_apply=True)
    update_bridge_settings(
        destination,
        {
            "sync_enabled": True,
            "routing_enabled": True,
            "auto_provision_agents": True,
        },
    )

    print(f"Configured: {destination}")
    print(f"Relay: {config.bridge.relay_url}")
    print(f"Human controller: {human_pubkey.lower()}")
    print(f"Bridge identity: {config.bridge.bridge_public_key}")
    print(
        f"Provisioned: {len(provision.identities_created)} new agent identities, "
        f"{provision.relay_members_added} new relay members"
    )
    _print_report(report)
    print("Channel sync, automatic agent provisioning, and mention routing are enabled.")
    return 0


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or (default or "")


def cmd_setup(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise ConfigError(
            "setup needs an interactive terminal; open the plugin's Setup overlay or use "
            "`buzzr bootstrap --help`"
        )
    destination = config_path(args.config)
    _ensure_config(destination)
    try:
        current = load_config(destination)
        default_relay = current.bridge.relay_url
    except ConfigError:
        default_relay = os.environ.get("BUZZ_RELAY_URL", "http://localhost:3000")

    print("buzzr setup")
    print("Your human private key is never requested or used.\n")
    relay = _ask("Buzz relay URL", default_relay)
    current_human = current.human_public_key() if 'current' in locals() else None
    human_pubkey = _ask("Your Buzz public key (64 hex)", current_human)
    compose_file = _ask("Buzz docker-compose.yml", "~/buzz/docker-compose.yml")
    agent_secrets = _ask(
        "Existing agent dotenv (optional; Enter to generate every missing identity)",
        "",
    )
    bootstrap_args = argparse.Namespace(
        config=args.config,
        state_dir=args.state_dir,
        human_pubkey=human_pubkey,
        relay=relay,
        compose_file=compose_file,
        managed_secrets_file=None,
        agent_secrets_file=agent_secrets or None,
        buzz_bin=None,
        nak_bin=None,
    )
    print("\nProvisioning relay members, agent ownership, and channels…")
    return cmd_bootstrap(bootstrap_args)


def cmd_doctor(args: argparse.Namespace) -> int:
    config, _store, topology = _load(args)
    print(f"Config: {config_path(args.config)}")
    print(f"Relay: {config.bridge.relay_url}")
    _print_credential_summary(config)
    bridge_key, bridge_auth = config.bridge_credentials()
    if not bridge_key or not config.bridge.bridge_public_key:
        print("Result: NOT READY — the bridge keypair is missing; run `buzzr bootstrap`")
        return 1
    if not config.human_public_key():
        print("Result: NOT READY — bridge.human_pubkey is missing")
        return 1

    client = BuzzClient(
        config.bridge.buzz_bin,
        config.bridge.relay_url,
        bridge_key,
        bridge_auth,
    )
    channels = client.list_channels()
    mapped = [agent for agent in topology.agents if agent.identity_id]
    mapped_with_keys = [
        agent
        for agent in mapped
        if agent.identity_id and config.identity_credentials(agent.identity_id)[0]
    ]
    print(f"Relay check: okay ({len(channels)} visible channels)")
    print(f"Herdr mapping: {len(topology.spaces)} Spaces, {len(mapped)}/{len(topology.agents)} agents")
    print(f"Reply credentials: {len(mapped_with_keys)}/{len(mapped)} mapped agents")
    missing_keys = sorted(
        identity_id
        for identity_id in config.identities
        if not config.identity_credentials(identity_id)[0]
    )
    if missing_keys:
        print(f"Result: NOT READY — missing private keys for: {', '.join(missing_keys)}")
        return 1
    if topology.warnings:
        print(f"Result: NOT READY — {len(topology.warnings)} topology warning(s)")
        return 1
    print(
        "Result: ACTIVE"
        if config.bridge.sync_enabled and config.bridge.routing_enabled
        else "Result: READY"
    )
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    _config, _store, topology = _load(args)
    if args.json:
        print(json.dumps(_topology_dict(topology), indent=2))
    else:
        _print_plan(topology)
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    config, store, topology = _load(args)
    report = reconcile(config, topology, store, force_apply=args.apply)
    _print_report(report)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config, store, topology = _load(args)
    state = store.load()
    bridge_key, _ = config.bridge_credentials()
    payload = {
        "relay_url": config.bridge.relay_url,
        "sync_enabled": config.bridge.sync_enabled,
        "routing_enabled": config.bridge.routing_enabled,
        "bridge_credential_available": bool(bridge_key),
        "bridge_public_key_available": bool(config.bridge.bridge_public_key),
        "human_pubkey_available": bool(config.human_public_key()),
        "credential_source": _credential_source(config),
        "spaces": len(topology.spaces),
        "agents": len(topology.agents),
        "mapped_agents": sum(1 for agent in topology.agents if agent.identity_id),
        "channels": state.get("channels", {}),
        "last_reconcile_at": state.get("last_reconcile_at"),
        "last_error": state.get("last_error"),
        "warnings": topology.warnings,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Relay: {payload['relay_url']}")
        print(f"Credentials: {payload['credential_source']}")
        print(f"Topology: {payload['spaces']} Spaces, {payload['agents']} agents")
        print(f"Mapped agents: {payload['mapped_agents']}/{payload['agents']}")
        print(f"Channel writes: {'enabled' if payload['sync_enabled'] else 'disabled'}")
        print(f"Message routing: {'enabled' if payload['routing_enabled'] else 'disabled'}")
        print(f"Bridge credential: {'available' if payload['bridge_credential_available'] else 'MISSING'}")
        print(f"Human pubkey: {'available' if payload['human_pubkey_available'] else 'MISSING'}")
        print(f"Known channels: {len(payload['channels'])}")
        if payload["last_error"]:
            print(f"Last error: {payload['last_error']}")
        for warning in payload["warnings"]:
            print(f"! {warning}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        while True:
            print("\033[2J\033[H", end="")
            try:
                cmd_status(args)
            except (ConfigError, CommandError) as exc:
                print(f"buzzr\n\n{exc}")
            print("\nRefreshes every 2 seconds · Ctrl-C to close")
            time.sleep(2)
    except KeyboardInterrupt:
        return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    persistent_config = config_path(args.config)
    config = load_config(persistent_config)
    store = StateStore(state_directory(args.state_dir))
    BridgeService(config, store, PLUGIN_ROOT, persistent_config).run()
    return 0


def cmd_reply(args: argparse.Namespace) -> int:
    content = sys.stdin.read() if args.content == "-" else args.content
    result = queue_reply(args.token, content)
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="buzzr")
    parser.add_argument("--config", help="override config.toml path")
    parser.add_argument("--state-dir", help="override persistent state directory")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-config", help="write a safe config template")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    configure = sub.add_parser(
        "configure", help="select the relay and credential source without copying secrets"
    )
    configure.add_argument("--relay", help="Buzz relay URL")
    source = configure.add_mutually_exclusive_group()
    source.add_argument(
        "--environment",
        action="store_true",
        help="read credentials from the Herdr server environment",
    )
    source.add_argument("--secrets-file", help="read credentials from a mode-0600 dotenv file")
    configure.add_argument("--private-key-env", default="BUZZ_PRIVATE_KEY")
    configure.add_argument("--auth-tag-env", default="BUZZ_AUTH_TAG")
    configure.add_argument(
        "--owner-pubkey",
        help="owner public key for owner-only inbound routing (inferred from BUZZ_AUTH_TAG)",
    )
    configure.set_defaults(func=cmd_configure)

    bootstrap = sub.add_parser(
        "bootstrap",
        help="provision bridge/agents, bind the human owner, create channels, and enable routing",
    )
    bootstrap.add_argument("--human-pubkey", help="human controller's 64-character public key")
    bootstrap.add_argument("--relay", help="public Buzz relay URL")
    bootstrap.add_argument("--compose-file", help="local Buzz docker-compose.yml")
    bootstrap.add_argument(
        "--managed-secrets-file",
        help="private dotenv buzzr may create/update (default: plugin config dir/secrets.env)",
    )
    bootstrap.add_argument(
        "--agent-secrets-file",
        help="optional existing mode-0600 dotenv containing imported agent keys",
    )
    bootstrap.add_argument("--buzz-bin", help="Buzz CLI binary")
    bootstrap.add_argument("--nak-bin", help="nak binary (default: nak)")
    bootstrap.set_defaults(func=cmd_bootstrap)

    setup = sub.add_parser("setup", help="run the interactive first-use setup")
    setup.set_defaults(func=cmd_setup)

    doctor = sub.add_parser("doctor", help="validate credentials, relay access, and mapping")
    doctor.set_defaults(func=cmd_doctor)

    plan = sub.add_parser("plan", help="preview Space/channel and agent/member mappings")
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=cmd_plan)

    reconcile_parser = sub.add_parser("reconcile", help="discover or synchronize Buzz channels")
    reconcile_parser.add_argument(
        "--apply", action="store_true", help="apply even when bridge.sync_enabled is false"
    )
    reconcile_parser.set_defaults(func=cmd_reconcile)

    status = sub.add_parser("status", help="show bridge readiness and current state")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    dashboard = sub.add_parser("dashboard", help="open a refreshing status display")
    dashboard.add_argument("--json", action="store_false", dest="json")
    dashboard.set_defaults(func=cmd_dashboard, json=False)

    daemon = sub.add_parser("daemon", help="run topology reconciliation and message routing")
    daemon.set_defaults(func=cmd_daemon)

    reply = sub.add_parser("reply", help="queue a reply through the credential-owning daemon")
    reply.add_argument("--token", required=True)
    reply.add_argument("--content", required=True)
    reply.set_defaults(func=cmd_reply)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (ConfigError, CommandError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
