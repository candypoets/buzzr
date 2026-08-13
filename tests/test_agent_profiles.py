from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from herdr_buzz.agent_profiles import build_agent_profile_declarations
from herdr_buzz.avatars import AvatarAsset, AvatarPack
from herdr_buzz.clients import BuzzClient, NostrTools
from herdr_buzz.config import BridgeConfig, Config, IdentityConfig
from herdr_buzz.sync import (
    IDENTITY_PROFILE_REFRESH_SECONDS,
    SyncReport,
    _sync_agent_profiles,
    _sync_identity_profiles,
)
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
    def test_buzz_upload_uses_the_identity_key_without_putting_it_in_argv(self) -> None:
        completed = subprocess.CompletedProcess(
            [],
            0,
            stdout='{"url":"https://relay.example/media/bee"}\n',
            stderr="",
        )
        with patch("herdr_buzz.clients.subprocess.run", return_value=completed) as run:
            result = BuzzClient(
                "buzz",
                "https://relay.example",
                SOL_PRIVATE,
            ).upload_file(Path("/tmp/bee.webp"))

        args = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(args, ["buzz", "upload", "file", "--file", "/tmp/bee.webp"])
        self.assertNotIn(SOL_PRIVATE, args)
        self.assertEqual(env["BUZZ_PRIVATE_KEY"], SOL_PRIVATE)
        self.assertEqual(result["url"], "https://relay.example/media/bee")

    def test_nak_profile_includes_the_picture_without_putting_secret_in_argv(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="event-id\n", stderr="")
        with patch("herdr_buzz.clients.subprocess.run", return_value=completed) as run:
            NostrTools("nak").publish_profile(
                "wss://relay.example",
                SOL_PRIVATE,
                name="Sol",
                about="Agent",
                picture="https://relay.example/media/bee",
            )

        args = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertNotIn(SOL_PRIVATE, args)
        self.assertEqual(env["NOSTR_SECRET_KEY"], SOL_PRIVATE)
        content = json.loads(args[args.index("--content") + 1])
        self.assertEqual(content["picture"], "https://relay.example/media/bee")

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

    def test_identity_profile_uploads_recraft_avatar_once_and_reuses_its_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bee.webp"
            path.write_bytes(b"bee")
            pack = AvatarPack(
                pack_id="test-bees",
                root=path.parent,
                assets=(
                    AvatarAsset(
                        asset_id="bee-01",
                        collection="test",
                        path=path,
                        sha256="e" * 64,
                    ),
                ),
            )
            config = identity_config()
            config.identities = {"sol": config.identities["sol"]}
            state = {"identity_profiles": {}, "avatar_uploads": {}}
            uploader = Mock()
            uploader.upload_file.return_value = {
                "url": "https://relay.example/media/bee"
            }
            publisher = Mock()
            with (
                patch("herdr_buzz.sync.load_avatar_pack", return_value=pack),
                patch("herdr_buzz.sync.BuzzClient", return_value=uploader),
                patch("herdr_buzz.sync.NostrTools", return_value=publisher),
            ):
                _sync_identity_profiles(
                    config,
                    state,
                    SyncReport(applied=True),
                    apply=True,
                    now=1_000,
                )
                _sync_identity_profiles(
                    config,
                    state,
                    SyncReport(applied=True),
                    apply=True,
                    now=1_000 + IDENTITY_PROFILE_REFRESH_SECONDS,
                )

            uploader.upload_file.assert_called_once_with(path)
            self.assertEqual(publisher.publish_profile.call_count, 2)
            self.assertEqual(
                publisher.publish_profile.call_args.kwargs["picture"],
                "https://relay.example/media/bee",
            )
            self.assertEqual(state["identity_profiles"]["sol"]["avatar_id"], "bee-01")

    def test_identity_profile_composes_layer_traits_from_the_pubkey(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = identity_config()
            config.identities = {"sol": config.identities["sol"]}
            state = {"identity_profiles": {}, "avatar_uploads": {}}
            uploader = Mock()
            uploader.upload_file.return_value = {
                "url": "https://relay.example/media/composed-bee"
            }
            publisher = Mock()
            with (
                patch("herdr_buzz.sync.BuzzClient", return_value=uploader),
                patch("herdr_buzz.sync.NostrTools", return_value=publisher),
            ):
                _sync_identity_profiles(
                    config,
                    state,
                    SyncReport(applied=True),
                    apply=True,
                    now=1_000,
                    avatar_output_dir=Path(directory),
                )

            uploaded_path = uploader.upload_file.call_args.args[0]
            self.assertTrue(uploaded_path.is_file())
            self.assertEqual(uploaded_path.suffix, ".png")
            self.assertEqual(
                set(state["identity_profiles"]["sol"]["avatar_traits"]),
                {"background", "body", "neck", "eyewear", "headwear"},
            )
            self.assertEqual(
                publisher.publish_profile.call_args.kwargs["picture"],
                "https://relay.example/media/composed-bee",
            )

    def test_identity_profile_can_disable_avatars(self) -> None:
        config = identity_config()
        config.bridge = BridgeConfig(
            human_pubkey=HUMAN,
            avatars_enabled=False,
        )
        config.identities = {"sol": config.identities["sol"]}
        state = {"identity_profiles": {}, "avatar_uploads": {}}
        publisher = Mock()
        with (
            patch("herdr_buzz.sync.BuzzClient") as uploader,
            patch("herdr_buzz.sync.NostrTools", return_value=publisher),
        ):
            _sync_identity_profiles(
                config,
                state,
                SyncReport(applied=True),
                apply=True,
                now=1_000,
            )

        uploader.assert_not_called()
        self.assertIsNone(publisher.publish_profile.call_args.kwargs["picture"])


if __name__ == "__main__":
    unittest.main()
