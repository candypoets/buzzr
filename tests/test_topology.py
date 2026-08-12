from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from herdr_buzz.config import (
    BridgeConfig,
    Config,
    ConfigError,
    IdentityConfig,
    load_config,
    parse_dotenv,
    append_identities,
    update_dotenv,
    update_bridge_settings,
)
from herdr_buzz.topology import build_topology, channel_slug, mentioned_pubkeys


def config() -> Config:
    return Config(
        bridge=BridgeConfig(exclude_spaces=("~",)),
        identities={
            "sol": IdentityConfig(
                identity_id="sol",
                display_name="Sol",
                aliases=("sol",),
                public_key="a" * 64,
                private_key_env="SOL_KEY",
            ),
            "k3": IdentityConfig(
                identity_id="k3",
                display_name="K3",
                aliases=("k3", "frontend"),
                public_key="b" * 64,
                private_key_env="K3_KEY",
            ),
        },
    )


class TopologyTests(unittest.TestCase):
    def test_space_maps_to_channel_and_tab_alias_maps_identity(self) -> None:
        snapshot = {
            "workspaces": [
                {"workspace_id": "w0", "label": "~", "number": 1},
                {"workspace_id": "w1", "label": "Cool Design", "number": 2},
            ],
            "tabs": [
                {"tab_id": "w1:t1", "workspace_id": "w1", "label": "sol"},
                {"tab_id": "w1:t2", "workspace_id": "w1", "label": "frontend"},
            ],
            "agents": [
                {
                    "workspace_id": "w1",
                    "tab_id": "w1:t1",
                    "pane_id": "w1:p1",
                    "terminal_id": "term1",
                    "agent": "codex",
                    "agent_status": "done",
                    "name": "project-coordinator",
                },
                {
                    "workspace_id": "w1",
                    "tab_id": "w1:t2",
                    "pane_id": "w1:p2",
                    "terminal_id": "term2",
                    "agent": "kimi",
                    "agent_status": "idle",
                },
            ],
        }
        topology = build_topology(snapshot, config())
        self.assertEqual([space.channel_name for space in topology.spaces], ["cool-design"])
        self.assertEqual([agent.identity_id for agent in topology.agents], ["sol", "k3"])
        self.assertEqual(topology.spaces[0].member_pubkeys, ("a" * 64, "b" * 64))

    def test_message_mentions_are_read_from_p_tags(self) -> None:
        event = {"tags": [["p", "a" * 64], ["e", "x"], ["p", "b" * 64, "relay"]]}
        self.assertEqual(mentioned_pubkeys(event), {"a" * 64, "b" * 64})

    def test_channel_slug(self) -> None:
        self.assertEqual(channel_slug(" Worktree: Cool Design! "), "worktree-cool-design")


class DotenvTests(unittest.TestCase):
    def test_secure_dotenv_is_parsed_without_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("A=one\nexport B='two three'\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(parse_dotenv(path), {"A": "one", "B": "two three"})

    def test_world_readable_dotenv_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.env"
            path.write_text("A=one\n", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(ConfigError):
                parse_dotenv(path)

    def test_environment_overrides_relay_and_supplies_standard_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[bridge]\nrelay_url = "http://old.invalid"\n', encoding="utf-8")
            with patch.dict(
                "os.environ",
                {
                    "BUZZ_RELAY_URL": "https://relay.example",
                    "BUZZ_PRIVATE_KEY": "private-placeholder",
                },
                clear=False,
            ):
                loaded = load_config(path)
                self.assertEqual(loaded.bridge.relay_url, "https://relay.example")
                self.assertEqual(loaded.owner_credentials()[0], "private-placeholder")

    def test_owner_pubkey_is_inferred_from_auth_tag(self) -> None:
        loaded = Config(
            bridge=BridgeConfig(bridge_auth_tag_env="BUZZ_AUTH_TAG"),
            secrets={
                "BUZZ_PRIVATE_KEY": "private-placeholder",
                "BUZZ_AUTH_TAG": '["auth","' + "c" * 64 + '","kind=1","sig"]',
            },
        )
        self.assertEqual(loaded.owner_public_key(), "c" * 64)

    def test_multiple_secret_files_are_merged_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.env"
            second = root / "second.env"
            first.write_text("A=one\nB=old\n", encoding="utf-8")
            second.write_text("B=new\n", encoding="utf-8")
            first.chmod(0o600)
            second.chmod(0o600)
            config_path = root / "config.toml"
            config_path.write_text(
                '[bridge]\nsecrets_files = ["first.env", "second.env"]\n',
                encoding="utf-8",
            )
            loaded = load_config(config_path)
            self.assertEqual(loaded.secrets, {"A": "one", "B": "new"})

    def test_dotenv_and_identity_updates_remain_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets.env"
            update_dotenv(secrets, {"B": "two", "A": "one"})
            update_dotenv(secrets, {"A": "new"})
            self.assertEqual(parse_dotenv(secrets), {"A": "new", "B": "two"})
            self.assertEqual(secrets.stat().st_mode & 0o777, 0o600)

            config_path = root / "config.toml"
            config_path.write_text("[bridge]\n", encoding="utf-8")
            append_identities(
                config_path,
                [
                    IdentityConfig(
                        identity_id="worker",
                        display_name="Worker",
                        aliases=("worker",),
                        public_key="d" * 64,
                        private_key_env="WORKER_KEY",
                    )
                ],
            )
            loaded = load_config(config_path)
            self.assertIn("worker", loaded.identities)
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_bridge_settings_update_preserves_identity_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[bridge]\nrelay_url = "http://old.invalid"\nsecrets_file = "/old"\n\n'
                '[identities.sol]\ndisplay_name = "Sol"\n',
                encoding="utf-8",
            )
            update_bridge_settings(
                path,
                {"relay_url": "https://relay.example", "secrets_file": None},
            )
            content = path.read_text(encoding="utf-8")
            self.assertIn('relay_url = "https://relay.example"', content)
            self.assertNotIn("secrets_file", content)
            self.assertIn("[identities.sol]", content)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
