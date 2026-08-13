from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from herdr_buzz.agent_profiles import build_agent_profile_declarations
from herdr_buzz.clients import NostrTools
from herdr_buzz.config import BridgeConfig, Config, IdentityConfig
from herdr_buzz.sync import SyncReport, _sync_agent_profiles
from herdr_buzz.topology import AgentBinding, SpaceBinding, Topology


HUMAN = "c" * 64
SOL_PUBLIC = "a" * 64
K3_PUBLIC = "b" * 64
SOL_PRIVATE = "1" * 64


def identity_config(*, respond_to: str = "owner-only") -> Config:
    return Config(
        bridge=BridgeConfig(
            human_pubkey=HUMAN,
            respond_to=respond_to,
            respond_to_allowlist=("d" * 64,),
        ),
        identities={
            "sol": IdentityConfig(
                identity_id="sol",
                display_name="Sol",
                aliases=("sol",),
                public_key=SOL_PUBLIC,
                private_key_env="SOL_KEY",
            ),
            "k3": IdentityConfig(
                identity_id="k3",
                display_name="K3",
                aliases=("k3",),
                public_key=K3_PUBLIC,
                private_key_env="K3_KEY",
            ),
        },
        secrets={"SOL_KEY": SOL_PRIVATE},
    )


def sol_binding(workspace_id: str, channel_name: str, pane_id: str) -> AgentBinding:
    return AgentBinding(
        workspace_id=workspace_id,
        workspace_label=channel_name,
        channel_name=channel_name,
        pane_id=pane_id,
        terminal_id=f"term-{pane_id}",
        tab_id=f"{workspace_id}:t1",
        tab_label="sol",
        runtime="codex",
        status="idle",
        agent_name="sol",
        display_label="sol",
        identity_id="sol",
        public_key=SOL_PUBLIC,
    )


class AgentProfileDeclarationTests(unittest.TestCase):
    def test_channels_are_aggregated_and_owner_gate_becomes_human_allowlist(self) -> None:
        topology = Topology(
            spaces=[
                SpaceBinding(
                    workspace_id="w1",
                    workspace_label="Alpha",
                    channel_name="alpha",
                    number=1,
                    agents=[sol_binding("w1", "alpha", "w1:p1")],
                ),
                SpaceBinding(
                    workspace_id="w2",
                    workspace_label="Beta",
                    channel_name="beta",
                    number=2,
                    agents=[sol_binding("w2", "beta", "w2:p1")],
                ),
            ]
        )
        declarations = build_agent_profile_declarations(
            identity_config(),
            topology,
            {
                "w1": {
                    "channel_id": "11111111-1111-1111-1111-111111111111",
                    "name": "alpha",
                },
                "w2": {
                    "channel_id": "22222222-2222-2222-2222-222222222222",
                    "name": "beta",
                },
            },
        )
        by_identity = {item.identity_id: item for item in declarations}

        sol = by_identity["sol"].content
        self.assertEqual(sol["channels"], ["alpha", "beta"])
        self.assertEqual(
            sol["channel_ids"],
            [
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
            ],
        )
        self.assertEqual(sol["respond_to"], "allowlist")
        self.assertEqual(sol["respond_to_allowlist"], [HUMAN])
        self.assertEqual(sol["status"], "online")
        self.assertEqual(sol["agent_type"], "codex")

        k3 = by_identity["k3"].content
        self.assertEqual(k3["channel_ids"], [])
        self.assertEqual(k3["status"], "offline")

    def test_explicit_allowlist_includes_the_human_like_runtime_routing(self) -> None:
        declarations = build_agent_profile_declarations(
            identity_config(respond_to="allowlist"),
            Topology(spaces=[]),
            {},
        )
        self.assertEqual(
            declarations[0].content["respond_to_allowlist"],
            [HUMAN, "d" * 64],
        )

    def test_nobody_is_a_valid_empty_allowlist_for_desktop(self) -> None:
        declarations = build_agent_profile_declarations(
            identity_config(respond_to="nobody"),
            Topology(spaces=[]),
            {},
        )
        self.assertEqual(declarations[0].content["respond_to"], "allowlist")
        self.assertEqual(declarations[0].content["respond_to_allowlist"], [])


class AgentProfilePublishingTests(unittest.TestCase):
    def test_nak_publishes_kind_10100_without_putting_secret_in_argv(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="event-id\n", stderr="")
        with patch("herdr_buzz.clients.subprocess.run", return_value=completed) as run:
            NostrTools("nak").publish_agent_profile(
                "wss://relay.example",
                SOL_PRIVATE,
                {"name": "Sol", "channel_ids": ["channel-id"]},
            )

        args = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(args[:5], ["nak", "event", "--auth", "--kind", "10100"])
        self.assertNotIn(SOL_PRIVATE, args)
        self.assertEqual(env["NOSTR_SECRET_KEY"], SOL_PRIVATE)
        content = json.loads(args[args.index("--content") + 1])
        self.assertEqual(content["channel_ids"], ["channel-id"])

    def test_sync_publishes_changed_content_once_and_caches_it(self) -> None:
        config = identity_config()
        config.identities = {"sol": config.identities["sol"]}
        topology = Topology(
            spaces=[
                SpaceBinding(
                    workspace_id="w1",
                    workspace_label="Alpha",
                    channel_name="alpha",
                    number=1,
                    agents=[sol_binding("w1", "alpha", "w1:p1")],
                )
            ]
        )
        state = {
            "channels": {
                "w1": {
                    "channel_id": "11111111-1111-1111-1111-111111111111",
                    "name": "alpha",
                }
            },
            "agent_profiles": {},
        }
        report = SyncReport(applied=True)
        publisher = Mock()
        with patch("herdr_buzz.sync.NostrTools", return_value=publisher):
            _sync_agent_profiles(config, topology, state, report, apply=True, now=1_000)
            _sync_agent_profiles(config, topology, state, report, apply=True, now=1_001)

        publisher.publish_agent_profile.assert_called_once()
        self.assertIn("sol", state["agent_profiles"])
        self.assertEqual(
            state["agent_profiles"]["sol"]["channel_ids"],
            ["11111111-1111-1111-1111-111111111111"],
        )


if __name__ == "__main__":
    unittest.main()
