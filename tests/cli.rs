//! Tests for CLI argument parsing, path resolution, and pure rendering/mapping
//! functions.
//! Interactive prompts and subprocess-heavy commands are not exercised here.

use std::collections::HashMap;
use std::sync::Mutex;

use buzzr::cli::{
    config_path, configure_updates, credential_source, parse, render_plan, render_report,
    render_status_text, setup_completion_text, state_directory, status_payload, topology_dict,
    BootstrapArgs, Command, ConfigureArgs, DeprovisionArgs, ParseFailure,
};
use buzzr::config::{BridgeConfig, Config};
use buzzr::sync::SyncReport;
use buzzr::topology::{AgentBinding, SpaceBinding, Topology};
use serde_json::{json, Value};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| word.to_string()).collect()
}

// --- parsing ---------------------------------------------------------------

#[test]
fn parses_global_flags_before_subcommand() {
    let parsed = parse(&args(&[
        "--config",
        "/tmp/c.toml",
        "--state-dir=/tmp/state",
        "status",
        "--json",
    ]))
    .expect("parses");
    assert_eq!(parsed.config.as_deref(), Some("/tmp/c.toml"));
    assert_eq!(parsed.state_dir.as_deref(), Some("/tmp/state"));
    assert_eq!(parsed.command, Command::Status { json: true });
}

#[test]
fn global_flags_after_subcommand_are_rejected_like_argparse() {
    let failure = parse(&args(&["doctor", "--config", "/nonexistent.toml"]))
        .expect_err("subparser does not know --config");
    match failure {
        ParseFailure::Error(message) => {
            assert_eq!(
                message,
                "unrecognized arguments: --config /nonexistent.toml"
            );
        }
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn parses_init_config_and_flag_forms() {
    let parsed = parse(&args(&["init-config", "--force"])).expect("parses");
    assert_eq!(parsed.command, Command::InitConfig { force: true });
    let parsed = parse(&args(&["init-config"])).expect("parses");
    assert_eq!(parsed.command, Command::InitConfig { force: false });
}

#[test]
fn parses_configure_with_argparse_defaults() {
    let parsed = parse(&args(&["configure", "--relay", "wss://example"])).expect("parses");
    assert_eq!(
        parsed.command,
        Command::Configure(ConfigureArgs {
            relay: Some("wss://example".to_string()),
            environment: false,
            secrets_file: None,
            private_key_env: "BUZZ_PRIVATE_KEY".to_string(),
            auth_tag_env: "BUZZ_AUTH_TAG".to_string(),
            owner_pubkey: None,
        })
    );
}

#[test]
fn configure_rejects_environment_with_secrets_file() {
    let failure = parse(&args(&[
        "configure",
        "--environment",
        "--secrets-file",
        "/tmp/s.env",
    ]))
    .expect_err("mutually exclusive");
    match failure {
        ParseFailure::Error(message) => {
            assert_eq!(
                message,
                "argument --secrets-file: not allowed with argument --environment"
            );
        }
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn parses_bootstrap_options_including_deprecated_nak_bin() {
    let parsed = parse(&args(&[
        "bootstrap",
        "--human-pubkey",
        &"ab".repeat(32),
        "--relay",
        "wss://relay",
        "--compose-file",
        "~/buzz/docker-compose.yml",
        "--nak-bin",
        "/usr/bin/nak",
    ]))
    .expect("nak-bin is still accepted");
    match parsed.command {
        Command::Bootstrap(BootstrapArgs {
            human_pubkey,
            relay,
            compose_file,
            nak_bin,
            ..
        }) => {
            assert_eq!(human_pubkey.as_deref(), Some("ab".repeat(32).as_str()));
            assert_eq!(relay.as_deref(), Some("wss://relay"));
            assert_eq!(compose_file.as_deref(), Some("~/buzz/docker-compose.yml"));
            assert_eq!(nak_bin.as_deref(), Some("/usr/bin/nak"));
        }
        other => panic!("expected bootstrap, got {other:?}"),
    }
}

#[test]
fn reply_requires_token_and_content() {
    let failure = parse(&args(&["reply"])).expect_err("required flags missing");
    match failure {
        ParseFailure::Error(message) => {
            assert_eq!(
                message,
                "the following arguments are required: --token, --content"
            );
        }
        other => panic!("expected error, got {other:?}"),
    }
    let parsed = parse(&args(&["reply", "--token", "t", "--content", "-"])).expect("parses");
    assert_eq!(
        parsed.command,
        Command::Reply {
            token: "t".to_string(),
            content: "-".to_string()
        }
    );
}

#[test]
fn parses_remaining_subcommands() {
    assert_eq!(
        parse(&args(&["reconcile", "--apply"])).unwrap().command,
        Command::Reconcile { apply: true }
    );
    assert_eq!(
        parse(&args(&["refresh-profiles", "--reupload"]))
            .unwrap()
            .command,
        Command::RefreshProfiles { reupload: true }
    );
    assert_eq!(
        parse(&args(&["plan", "--json"])).unwrap().command,
        Command::Plan { json: true }
    );
    assert_eq!(parse(&args(&["setup"])).unwrap().command, Command::Setup);
    assert_eq!(parse(&args(&["doctor"])).unwrap().command, Command::Doctor);
    assert_eq!(
        parse(&args(&["dashboard"])).unwrap().command,
        Command::Dashboard
    );
    assert_eq!(parse(&args(&["daemon"])).unwrap().command, Command::Daemon);
    assert_eq!(parse(&args(&["stop"])).unwrap().command, Command::Stop);
    assert_eq!(
        parse(&args(&["deactivate"])).unwrap().command,
        Command::Deactivate
    );
    assert_eq!(
        parse(&args(&[
            "deprovision",
            "--apply",
            "--confirm-relay",
            "wss://relay",
            "--delete-local-data",
            "--json",
        ]))
        .unwrap()
        .command,
        Command::Deprovision(DeprovisionArgs {
            apply: true,
            confirm_relay: Some("wss://relay".to_string()),
            delete_local_data: true,
            json: true,
            interactive: false,
        })
    );
    assert_eq!(
        parse(&args(&["deprovision", "--interactive"]))
            .unwrap()
            .command,
        Command::Deprovision(DeprovisionArgs {
            interactive: true,
            ..DeprovisionArgs::default()
        })
    );
}

#[test]
fn interactive_deprovision_rejects_noninteractive_flags() {
    let failure = parse(&args(&["deprovision", "--interactive", "--apply"]))
        .expect_err("interactive confirmation owns the apply flow");
    assert_eq!(
        failure,
        ParseFailure::Error(
            "argument --interactive: not allowed with apply/confirmation/output flags".to_string()
        )
    );
}

#[test]
fn missing_command_and_unknown_command_error_like_argparse() {
    match parse(&args(&[])).expect_err("command required") {
        ParseFailure::Error(message) => {
            assert_eq!(message, "the following arguments are required: command");
        }
        other => panic!("expected error, got {other:?}"),
    }
    match parse(&args(&["frobnicate"])).expect_err("invalid choice") {
        ParseFailure::Error(message) => {
            assert!(message.starts_with("argument command: invalid choice: 'frobnicate'"));
            assert!(message.contains("'init-config'"));
        }
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn help_is_requested_with_dash_h() {
    match parse(&args(&["--help"])).expect_err("help") {
        ParseFailure::Help(text) => {
            assert!(text.contains("usage: buzzr"));
            assert!(text.contains("init-config"));
            assert!(text.contains("refresh-profiles"));
            assert!(text.contains("deprovision"));
        }
        other => panic!("expected help, got {other:?}"),
    }
    match parse(&args(&["bootstrap", "-h"])).expect_err("sub help") {
        ParseFailure::Help(text) => {
            assert!(text.contains("usage: buzzr bootstrap"));
            assert!(text.contains("--human-pubkey"));
        }
        other => panic!("expected help, got {other:?}"),
    }
}

#[test]
fn setup_completion_explains_how_to_use_the_bridge() {
    let started = setup_completion_text("buzzr", true);
    assert!(started.contains("Setup complete."));
    assert!(started.contains("Routing daemon: started."));
    assert!(started.contains("open Buzz"));
    assert!(started.contains("@mention one of your agents"));

    let manual = setup_completion_text("buzzr-dev", false);
    assert!(manual.contains("herdr plugin action invoke start --plugin buzzr-dev"));
}

// --- config/state path resolution -------------------------------------------

/// Env-mutating tests must not run concurrently.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard(Vec<(&'static str, Option<String>)>);

impl EnvGuard {
    fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
        let saved = vars
            .iter()
            .map(|(key, value)| {
                let previous = std::env::var(key).ok();
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
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

#[test]
fn config_path_resolution_order_is_stable() {
    let _lock = ENV_LOCK.lock().unwrap();
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_CONFIG", Some("~/custom.toml")),
            ("HERDR_PLUGIN_CONFIG_DIR", Some("/plugin-config")),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
            ("HOME", Some("/home/tester")),
        ]);
        // Explicit flag wins over everything.
        assert_eq!(
            config_path(Some("/flag.toml")),
            std::path::PathBuf::from("/flag.toml")
        );
        // Environment override next, with ~ expansion.
        assert_eq!(
            config_path(None),
            std::path::PathBuf::from("/home/tester/custom.toml")
        );
    }
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_CONFIG", None),
            ("HERDR_BUZZ_CONFIG", None),
            ("HERDR_PLUGIN_CONFIG_DIR", Some("/plugin-config")),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
        ]);
        assert_eq!(
            config_path(None),
            std::path::PathBuf::from("/plugin-config/config.toml")
        );
    }
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_CONFIG", None),
            ("HERDR_BUZZ_CONFIG", None),
            ("HERDR_PLUGIN_CONFIG_DIR", None),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
        ]);
        assert_eq!(
            config_path(None),
            std::path::PathBuf::from("/plugin-root/config.toml")
        );
    }
}

#[test]
fn state_directory_resolution_order_is_stable() {
    let _lock = ENV_LOCK.lock().unwrap();
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_STATE_DIR", Some("/env-state")),
            ("HERDR_PLUGIN_STATE_DIR", Some("/plugin-state")),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
        ]);
        assert_eq!(
            state_directory(Some("/flag-state")),
            std::path::PathBuf::from("/flag-state")
        );
        assert_eq!(
            state_directory(None),
            std::path::PathBuf::from("/env-state")
        );
    }
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_STATE_DIR", None),
            ("HERDR_BUZZ_STATE_DIR", None),
            ("HERDR_PLUGIN_STATE_DIR", Some("/plugin-state")),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
        ]);
        assert_eq!(
            state_directory(None),
            std::path::PathBuf::from("/plugin-state")
        );
    }
    {
        let _env = EnvGuard::set(&[
            ("BUZZR_STATE_DIR", None),
            ("HERDR_BUZZ_STATE_DIR", None),
            ("HERDR_PLUGIN_STATE_DIR", None),
            ("HERDR_PLUGIN_ROOT", Some("/plugin-root")),
        ]);
        assert_eq!(
            state_directory(None),
            std::path::PathBuf::from("/plugin-root/.state")
        );
    }
}

// --- configure mapping --------------------------------------------------------

#[test]
fn configure_updates_map_flags_to_bridge_keys() {
    let updates = configure_updates(&ConfigureArgs {
        relay: Some("wss://relay".to_string()),
        environment: true,
        private_key_env: "MY_KEY".to_string(),
        auth_tag_env: "MY_TAG".to_string(),
        owner_pubkey: Some("AB".repeat(32)),
        ..ConfigureArgs::default()
    });
    let map: HashMap<String, Option<Value>> = updates.into_iter().collect();
    assert_eq!(map["relay_url"], Some(json!("wss://relay")));
    // --environment clears the dotenv credential sources.
    assert_eq!(map["secrets_file"], None);
    assert_eq!(map["secrets_files"], None);
    assert_eq!(map["bridge_private_key_env"], Some(json!("MY_KEY")));
    assert_eq!(map["bridge_auth_tag_env"], Some(json!("MY_TAG")));
    // Owner pubkey is normalized to lowercase.
    assert_eq!(map["human_pubkey"], Some(json!("ab".repeat(32))));
}

#[test]
fn configure_updates_secrets_file_resolves_to_list() {
    let directory = tempfile::tempdir().unwrap();
    let secrets = directory.path().join("secrets.env");
    std::fs::write(&secrets, "").unwrap();
    let updates = configure_updates(&ConfigureArgs {
        secrets_file: Some(secrets.to_string_lossy().into_owned()),
        ..ConfigureArgs::default()
    });
    let map: HashMap<String, Option<Value>> = updates.into_iter().collect();
    assert_eq!(
        map["secrets_files"],
        Some(json!([secrets.canonicalize().unwrap().to_string_lossy()]))
    );
    assert_eq!(map["secrets_file"], None);
    assert!(!map.contains_key("relay_url"));
}

// --- rendering ---------------------------------------------------------------

fn test_topology() -> Topology {
    Topology {
        spaces: vec![SpaceBinding {
            workspace_id: "w1".to_string(),
            workspace_label: "Cool Design".to_string(),
            channel_name: "cool-design".to_string(),
            number: 1,
            agents: vec![
                AgentBinding {
                    workspace_id: "w1".to_string(),
                    workspace_label: "Cool Design".to_string(),
                    channel_name: "cool-design".to_string(),
                    pane_id: "w1:p1".to_string(),
                    terminal_id: "t1".to_string(),
                    tab_id: "w1:t1".to_string(),
                    tab_label: "sol".to_string(),
                    runtime: "codex".to_string(),
                    status: "idle".to_string(),
                    agent_name: Some("sol".to_string()),
                    display_label: "sol".to_string(),
                    identity_id: Some("sol".to_string()),
                    public_key: Some("a".repeat(64)),
                },
                AgentBinding {
                    workspace_id: "w1".to_string(),
                    workspace_label: "Cool Design".to_string(),
                    channel_name: "cool-design".to_string(),
                    pane_id: "w1:p2".to_string(),
                    terminal_id: "t2".to_string(),
                    tab_id: "w1:t2".to_string(),
                    tab_label: "2".to_string(),
                    runtime: "kimi".to_string(),
                    status: "running".to_string(),
                    agent_name: None,
                    display_label: "kimi-p2".to_string(),
                    identity_id: None,
                    public_key: None,
                },
            ],
        }],
        warnings: vec!["something looks off".to_string()],
    }
}

#[test]
fn render_plan_has_expected_layout() {
    let rendered = render_plan(&test_topology());
    let expected = "Herdr → Buzz: 1 Spaces, 2 agents\n\
        \n#cool-design  (w1, Cool Design)\n\
        \u{20}\u{20}· sol → sol [codex/idle] w1:p1\n\
        \u{20}\u{20}· kimi-p2 → UNMAPPED [kimi/running] w1:p2\n\
        \nWarnings:\n\
        \u{20}\u{20}! something looks off\n";
    assert_eq!(rendered, expected);
}

#[test]
fn render_plan_handles_empty_space() {
    let mut topology = test_topology();
    topology.spaces[0].agents.clear();
    topology.warnings.clear();
    let rendered = render_plan(&topology);
    assert!(rendered.contains("  · no agents\n"));
    assert!(!rendered.contains("Warnings:"));
}

#[test]
fn render_report_has_expected_layout() {
    let report = SyncReport {
        applied: true,
        actions: vec!["create #cool-design".to_string()],
        warnings: vec!["watch out".to_string()],
    };
    assert_eq!(
        render_report(&report),
        "mode: APPLY\n  · create #cool-design\n  ! watch out\n"
    );
    let idle = SyncReport::new(false);
    assert_eq!(
        render_report(&idle),
        "mode: PREVIEW\n  · already reconciled\n"
    );
}

#[test]
fn topology_dict_has_expected_shape() {
    let dict = topology_dict(&test_topology());
    assert_eq!(dict["warnings"], json!(["something looks off"]));
    let space = &dict["spaces"][0];
    assert_eq!(space["workspace_id"], json!("w1"));
    assert_eq!(space["space"], json!("Cool Design"));
    assert_eq!(space["channel"], json!("cool-design"));
    assert_eq!(
        space["agents"][0],
        json!({
            "label": "sol",
            "identity": "sol",
            "runtime": "codex",
            "status": "idle",
            "pane_id": "w1:p1",
        })
    );
    assert_eq!(space["agents"][1]["identity"], Value::Null);
}

#[test]
fn status_payload_and_text_rendering() {
    let config = Config {
        bridge: BridgeConfig {
            relay_url: "wss://relay".to_string(),
            sync_enabled: true,
            routing_enabled: false,
            ..BridgeConfig::default()
        },
        identities: HashMap::new(),
        secrets: HashMap::new(),
    };
    let state = json!({
        "channels": {"w1": {"channel_id": "c1"}},
        "identity_profiles": {"sol": {}},
        "avatar_uploads": {},
        "last_reconcile_at": 123,
        "last_error": "boom",
    });
    let payload = status_payload(&config, &state, &test_topology());
    assert_eq!(payload["relay_url"], json!("wss://relay"));
    assert_eq!(payload["sync_enabled"], json!(true));
    assert_eq!(payload["routing_enabled"], json!(false));
    assert_eq!(payload["bridge_credential_available"], json!(false));
    assert_eq!(payload["human_pubkey_available"], json!(false));
    assert_eq!(payload["credential_source"], json!("inherited environment"));
    assert_eq!(payload["spaces"], json!(1));
    assert_eq!(payload["agents"], json!(2));
    assert_eq!(payload["mapped_agents"], json!(1));
    assert_eq!(payload["profiled_identities"], json!(1));
    assert_eq!(payload["uploaded_avatars"], json!(0));
    assert_eq!(payload["last_reconcile_at"], json!(123));
    assert_eq!(payload["last_error"], json!("boom"));

    let text = render_status_text(&payload);
    let expected = "Relay: wss://relay\n\
        Credentials: inherited environment\n\
        Topology: 1 Spaces, 2 agents\n\
        Mapped agents: 1/2\n\
        Channel writes: enabled\n\
        Message routing: disabled\n\
        Bridge credential: MISSING\n\
        Human pubkey: MISSING\n\
        Known channels: 1\n\
        Managed profiles: 1\n\
        Uploaded avatars: 0\n\
        Last error: boom\n\
        ! something looks off\n";
    assert_eq!(text, expected);
}

#[test]
fn status_text_omits_null_last_error() {
    let payload = json!({
        "relay_url": "wss://relay",
        "sync_enabled": false,
        "routing_enabled": false,
        "bridge_credential_available": true,
        "human_pubkey_available": true,
        "credential_source": "inherited environment",
        "spaces": 0,
        "agents": 0,
        "mapped_agents": 0,
        "channels": {},
        "profiled_identities": 0,
        "uploaded_avatars": 0,
        "last_reconcile_at": null,
        "last_error": null,
        "warnings": [],
    });
    let text = render_status_text(&payload);
    assert!(!text.contains("Last error"));
    assert!(text.contains("Bridge credential: available"));
}

#[test]
fn credential_source_lists_secrets_files() {
    let mut config = Config::default();
    assert_eq!(credential_source(&config), "inherited environment");
    config.bridge.secrets_files = vec![
        std::path::PathBuf::from("/a.env"),
        std::path::PathBuf::from("/b.env"),
    ];
    assert_eq!(credential_source(&config), "/a.env, /b.env");
}
