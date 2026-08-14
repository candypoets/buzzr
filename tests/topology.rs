//! Topology mapping tests.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use buzzr::config::{
    append_identities, load_config, normalize_human_pubkey, parse_dotenv, update_bridge_settings,
    update_dotenv, BridgeConfig, Config, IdentityConfig,
};
use buzzr::state::StateStore;
use buzzr::topology::{build_topology, channel_slug, mentioned_pubkeys};
use fs2::FileExt;
use serde_json::{json, Value};

fn config() -> Config {
    let mut identities = HashMap::new();
    identities.insert(
        "sol".to_string(),
        IdentityConfig {
            identity_id: "sol".to_string(),
            display_name: "Sol".to_string(),
            aliases: vec!["sol".to_string()],
            public_key: "a".repeat(64),
            private_key_env: "SOL_KEY".to_string(),
            auth_tag_env: None,
        },
    );
    identities.insert(
        "k3".to_string(),
        IdentityConfig {
            identity_id: "k3".to_string(),
            display_name: "K3".to_string(),
            aliases: vec!["k3".to_string(), "frontend".to_string()],
            public_key: "b".repeat(64),
            private_key_env: "K3_KEY".to_string(),
            auth_tag_env: None,
        },
    );
    Config {
        bridge: BridgeConfig {
            exclude_spaces: vec!["~".to_string()],
            ..BridgeConfig::default()
        },
        identities,
        secrets: HashMap::new(),
    }
}

/// Restore environment variables on drop (mirrors `patch.dict`).
struct EnvGuard(Vec<(&'static str, Option<String>)>);

impl EnvGuard {
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let saved = vars
            .iter()
            .map(|(key, value)| {
                let previous = std::env::var(key).ok();
                std::env::set_var(key, value);
                (*key, previous)
            })
            .collect();
        EnvGuard(saved)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn human_pubkeys_accept_npub_and_normalize_to_hex() {
    const HEX: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    const NPUB: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";

    assert_eq!(normalize_human_pubkey(NPUB).unwrap(), HEX);
    assert_eq!(normalize_human_pubkey(&HEX.to_uppercase()).unwrap(), HEX);
    assert!(normalize_human_pubkey("not-a-public-key").is_err());
}

#[test]
fn space_maps_to_channel_and_tab_alias_maps_identity() {
    let snapshot = json!({
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
    });
    let topology = build_topology(&snapshot, &config());
    let channel_names: Vec<&str> = topology
        .spaces
        .iter()
        .map(|space| space.channel_name.as_str())
        .collect();
    assert_eq!(channel_names, ["cool-design"]);
    let identity_ids: Vec<Option<&str>> = topology
        .agents()
        .iter()
        .map(|agent| agent.identity_id.as_deref())
        .collect();
    assert_eq!(identity_ids, [Some("sol"), Some("k3")]);
    assert_eq!(
        topology.spaces[0].member_pubkeys(),
        vec!["a".repeat(64), "b".repeat(64)]
    );
}

#[test]
fn message_mentions_are_read_from_p_tags() {
    let event =
        json!({"tags": [["p", "a".repeat(64)], ["e", "x"], ["p", "b".repeat(64), "relay"]]});
    let mentions = mentioned_pubkeys(&event);
    let expected: std::collections::HashSet<String> =
        ["a".repeat(64), "b".repeat(64)].into_iter().collect();
    assert_eq!(mentions, expected);
}

#[test]
fn channel_slug_normalizes_labels() {
    assert_eq!(
        channel_slug(" Worktree: Cool Design! "),
        "worktree-cool-design"
    );
}

#[test]
fn state_load_migrates_the_schema_version_and_preserves_data() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.json");
    std::fs::write(&path, r#"{"version":1,"channels":{"w1":{"name":"alpha"}}}"#).unwrap();
    let loaded = StateStore::new(directory.path().to_path_buf())
        .load()
        .unwrap();
    assert_eq!(loaded["version"], json!(5));
    assert_eq!(loaded["channels"]["w1"]["name"], json!("alpha"));
    assert_eq!(loaded["agent_profiles"], json!({}));
    assert_eq!(loaded["identity_profiles"], json!({}));
    assert_eq!(loaded["avatar_uploads"], json!({}));
    assert_eq!(loaded["managed_resources"]["identities"], json!({}));
}

#[test]
fn state_lock_serializes_independent_writers() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = StateStore::new(directory.path().to_path_buf());
    store
        .with_lock(|| {
            let lock_path = directory.path().join("state.lock");
            let contender = std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&lock_path)
                .unwrap();
            assert!(contender.try_lock_exclusive().is_err());
        })
        .unwrap();
    assert_eq!(file_mode(&directory.path().join("state.lock")), 0o600);
}

#[test]
fn secure_dotenv_is_parsed_without_expansion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.env");
    std::fs::write(&path, "A=one\nexport B='two three'\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let parsed = parse_dotenv(&path).unwrap();
    let expected: HashMap<String, String> = [
        ("A".to_string(), "one".to_string()),
        ("B".to_string(), "two three".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(parsed, expected);
}

#[test]
fn world_readable_dotenv_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.env");
    std::fs::write(&path, "A=one\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(parse_dotenv(&path).is_err());
}

#[test]
fn environment_overrides_relay_and_supplies_standard_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[bridge]\nrelay_url = \"http://old.invalid\"\n").unwrap();
    let _guard = EnvGuard::set(&[
        ("BUZZ_RELAY_URL", "https://relay.example"),
        ("BUZZ_PRIVATE_KEY", "private-placeholder"),
    ]);
    let loaded = load_config(&path).unwrap();
    assert_eq!(loaded.bridge.relay_url, "https://relay.example");
    assert_eq!(
        loaded.owner_credentials().0,
        Some("private-placeholder".to_string())
    );
}

#[test]
fn owner_pubkey_is_inferred_from_auth_tag() {
    let mut secrets = HashMap::new();
    secrets.insert(
        "BUZZ_PRIVATE_KEY".to_string(),
        "private-placeholder".to_string(),
    );
    secrets.insert(
        "BUZZ_AUTH_TAG".to_string(),
        format!("[\"auth\",\"{}\",\"kind=1\",\"sig\"]", "c".repeat(64)),
    );
    let loaded = Config {
        bridge: BridgeConfig {
            bridge_auth_tag_env: Some("BUZZ_AUTH_TAG".to_string()),
            ..BridgeConfig::default()
        },
        identities: HashMap::new(),
        secrets,
    };
    assert_eq!(loaded.owner_public_key(), Some("c".repeat(64)));
}

#[test]
fn multiple_secret_files_are_merged_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let first = root.join("first.env");
    let second = root.join("second.env");
    std::fs::write(&first, "A=one\nB=old\n").unwrap();
    std::fs::write(&second, "B=new\n").unwrap();
    std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        "[bridge]\nsecrets_files = [\"first.env\", \"second.env\"]\n",
    )
    .unwrap();
    let loaded = load_config(&config_path).unwrap();
    let expected: HashMap<String, String> = [
        ("A".to_string(), "one".to_string()),
        ("B".to_string(), "new".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(loaded.secrets, expected);
}

#[test]
fn dotenv_and_identity_updates_remain_private() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let secrets = root.join("secrets.env");
    update_dotenv(
        &secrets,
        &[
            ("B".to_string(), "two".to_string()),
            ("A".to_string(), "one".to_string()),
        ],
    )
    .unwrap();
    update_dotenv(&secrets, &[("A".to_string(), "new".to_string())]).unwrap();
    let parsed = parse_dotenv(&secrets).unwrap();
    assert_eq!(parsed.get("A"), Some(&"new".to_string()));
    assert_eq!(parsed.get("B"), Some(&"two".to_string()));
    assert_eq!(file_mode(&secrets), 0o600);

    let config_path = root.join("config.toml");
    std::fs::write(&config_path, "[bridge]\n").unwrap();
    append_identities(
        &config_path,
        &[IdentityConfig {
            identity_id: "worker".to_string(),
            display_name: "Worker".to_string(),
            aliases: vec!["worker".to_string()],
            public_key: "d".repeat(64),
            private_key_env: "WORKER_KEY".to_string(),
            auth_tag_env: None,
        }],
    )
    .unwrap();
    let loaded = load_config(&config_path).unwrap();
    assert!(loaded.identities.contains_key("worker"));
    assert_eq!(file_mode(&config_path), 0o600);
}

#[test]
fn bridge_settings_update_preserves_identity_tables() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        "[bridge]\nrelay_url = \"http://old.invalid\"\nsecrets_file = \"/old\"\n\n\
         [identities.sol]\ndisplay_name = \"Sol\"\n",
    )
    .unwrap();
    update_bridge_settings(
        &path,
        &[
            (
                "relay_url".to_string(),
                Some(Value::String("https://relay.example".to_string())),
            ),
            ("secrets_file".to_string(), None),
        ],
    )
    .unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("relay_url = \"https://relay.example\""));
    assert!(!content.contains("secrets_file"));
    assert!(content.contains("[identities.sol]"));
    assert_eq!(file_mode(&path), 0o600);
}
