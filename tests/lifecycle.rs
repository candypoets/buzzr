//! Lifecycle integration tests against fake Buzz and Docker command surfaces.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use buzzr::config::load_config;
use buzzr::lifecycle::apply_deprovision;
use buzzr::state::{default_state, StateStore};
use serde_json::json;

const BRIDGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AGENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HUMAN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
    store: StateStore,
    buzz_calls: PathBuf,
    docker_calls: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_path_buf();
    let buzz_calls = root.join("buzz.calls");
    let docker_calls = root.join("docker.calls");
    let buzz = root.join("buzz");
    executable(
        &buzz,
        &format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1 $2\" = \"channels members\" ]; then\n\
               printf '%s\\n' '[{{\"pubkey\":\"{AGENT}\",\"role\":\"bot\"}}]'\n\
             else\n\
               printf '%s\\n' '{{}}'\n\
             fi\n",
            buzz_calls.display()
        ),
    );
    let docker = root.join("docker");
    executable(
        &docker,
        &format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> '{}'\n\
             service=\"$6\"\nshift 6\n\
             if [ \"$service\" = relay ]; then\n\
               case \"$1 $2\" in\n\
                 \"buzz-admin list-members\") printf '%s\\n%s\\n' '{BRIDGE}' '{AGENT}' ;;\n\
                 \"buzz-admin remove-member\") : ;;\n\
                 *) exit 9 ;;\n\
               esac\n\
             elif [ \"$service\" = postgres ]; then\n\
               sql=\"\"\nfor argument in \"$@\"; do sql=\"$argument\"; done\n\
               case \"$sql\" in\n\
                 *\"SELECT DISTINCT community_id\"*) printf '%s\\n' \
                   '11111111-2222-3333-4444-555555555555' ;;\n\
                 *\"UPDATE users SET agent_owner_pubkey = NULL\"*) printf '%s\\n' 'cleared' ;;\n\
                 *) exit 8 ;;\n\
               esac\n\
             else\nexit 7\nfi\n",
            docker_calls.display()
        ),
    );
    std::fs::write(root.join("docker-compose.yml"), "services: {}\n").unwrap();
    let secrets = root.join("secrets.env");
    std::fs::write(
        &secrets,
        format!(
            "BUZZR_BRIDGE_PRIVATE_KEY={}\nBUZZR_AGENT_SOL_PRIVATE_KEY={}\n",
            "1".repeat(64),
            "2".repeat(64)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[bridge]\nrelay_url = \"wss://relay.example\"\nbuzz_bin = \"{}\"\n\
             human_pubkey = \"{HUMAN}\"\nbridge_public_key = \"{BRIDGE}\"\n\
             bridge_private_key_env = \"BUZZR_BRIDGE_PRIVATE_KEY\"\ncompose_file = \"{}\"\n\
             managed_secrets_file = \"{}\"\nsecrets_files = [\"{}\"]\n\
             sync_enabled = true\nrouting_enabled = true\nauto_provision_agents = true\n\n\
             [identities.sol]\ndisplay_name = \"Sol\"\naliases = [\"sol\"]\n\
             public_key = \"{AGENT}\"\nprivate_key_env = \"BUZZR_AGENT_SOL_PRIVATE_KEY\"\n",
            buzz.display(),
            root.join("docker-compose.yml").display(),
            secrets.display(),
            secrets.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let store = StateStore::new(root.join("state"));
    let mut state = default_state();
    state["channels"] = json!({
        "w1": {
            "channel_id": "11111111-1111-1111-1111-111111111111",
            "name": "created",
            "origin": "created"
        },
        "w2": {
            "channel_id": "22222222-2222-2222-2222-222222222222",
            "name": "adopted",
            "origin": "adopted"
        }
    });
    state["managed_resources"]["identities"] = json!({
        BRIDGE: {"origin": "generated", "identity_kind": "bridge", "identity_id": "bridge", "archived": false},
        AGENT: {"origin": "generated", "identity_kind": "agent", "identity_id": "sol", "archived": false}
    });
    state["managed_resources"]["relay_members"] = json!({
        BRIDGE: {"origin": "added"}, AGENT: {"origin": "added"}
    });
    state["managed_resources"]["ownerships"] = json!({
        BRIDGE: {"origin": "assigned", "owner_pubkey": HUMAN},
        AGENT: {"origin": "assigned", "owner_pubkey": HUMAN}
    });
    state["managed_resources"]["channel_memberships"] = json!({
        "22222222-2222-2222-2222-222222222222": {
            AGENT: {"origin": "added", "role": "bot"}
        }
    });
    store.save(&state).unwrap();

    Fixture {
        _directory: directory,
        root,
        config_path,
        store,
        buzz_calls,
        docker_calls,
    }
}

#[test]
fn apply_archives_owned_resources_and_preserves_adopted_channel() {
    let fixture = fixture();
    let config = load_config(&fixture.config_path).unwrap();
    let previous_path = std::env::var_os("PATH");
    let mut search_path = vec![fixture.root.clone()];
    if let Some(path) = &previous_path {
        search_path.extend(std::env::split_paths(path));
    }
    std::env::set_var("PATH", std::env::join_paths(search_path).unwrap());
    std::env::set_var("BUZZR_RUNTIME_DIR", fixture.root.join("runtime"));
    let plan = apply_deprovision(&fixture.config_path, &config, &fixture.store, false).unwrap();
    std::env::remove_var("BUZZR_RUNTIME_DIR");
    match previous_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }

    assert_eq!(plan.relay_url, "wss://relay.example");
    let buzz_calls = std::fs::read_to_string(&fixture.buzz_calls).unwrap();
    assert!(buzz_calls.contains("channels archive --channel 11111111-1111-1111-1111-111111111111"));
    assert!(buzz_calls
        .contains("channels remove-member --channel 22222222-2222-2222-2222-222222222222"));
    assert!(buzz_calls.contains(&format!("agents archive {BRIDGE} --reason retired")));
    assert!(buzz_calls.contains(&format!("agents archive {AGENT} --reason retired")));

    let docker_calls = std::fs::read_to_string(&fixture.docker_calls).unwrap();
    assert_eq!(docker_calls.matches("buzz-admin remove-member").count(), 2);
    assert_eq!(
        docker_calls
            .matches("UPDATE users SET agent_owner_pubkey = NULL")
            .count(),
        2
    );

    let state = fixture.store.load().unwrap();
    assert!(state["channels"].get("w1").is_none());
    assert_eq!(state["channels"]["w2"]["origin"], json!("adopted"));
    assert_eq!(
        state["managed_resources"]["identities"][BRIDGE]["archived"],
        json!(true)
    );
    assert_eq!(
        state["managed_resources"]["identities"][AGENT]["archived"],
        json!(true)
    );
    assert_eq!(state["managed_resources"]["relay_members"], json!({}));
    assert_eq!(state["managed_resources"]["ownerships"], json!({}));
    assert_eq!(state["managed_resources"]["channel_memberships"], json!({}));
    let config = load_config(&fixture.config_path).unwrap();
    assert!(!config.bridge.sync_enabled);
    assert!(!config.bridge.routing_enabled);
    assert!(!config.bridge.auto_provision_agents);
}

#[test]
fn cli_preview_is_read_only_and_wrong_relay_confirmation_fails_closed() {
    let fixture = fixture();
    let binary = env!("CARGO_BIN_EXE_buzzr");
    let preview = Command::new(binary)
        .args([
            "--config",
            fixture.config_path.to_str().unwrap(),
            "--state-dir",
            fixture.store.directory.to_str().unwrap(),
            "deprovision",
        ])
        .output()
        .unwrap();
    assert!(preview.status.success());
    let output = String::from_utf8_lossy(&preview.stdout);
    assert!(output.contains("mode: PREVIEW"));
    assert!(output.contains("archive buzzr-created #created"));
    assert!(output.contains("preserving adopted #adopted"));
    assert!(!fixture.buzz_calls.exists());
    assert!(!fixture.docker_calls.exists());

    let rejected = Command::new(binary)
        .args([
            "--config",
            fixture.config_path.to_str().unwrap(),
            "--state-dir",
            fixture.store.directory.to_str().unwrap(),
            "deprovision",
            "--apply",
            "--confirm-relay",
            "wss://wrong.example",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("--confirm-relay must exactly equal wss://relay.example"));
    assert!(!fixture.buzz_calls.exists());
    assert!(!fixture.docker_calls.exists());
}

#[test]
fn preview_does_not_self_authorize_an_unrelated_state_directory() {
    let fixture = fixture();
    let unrelated = fixture.root.join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    std::fs::write(unrelated.join("keep.txt"), "user data\n").unwrap();

    let preview = Command::new(env!("CARGO_BIN_EXE_buzzr"))
        .args([
            "--config",
            fixture.config_path.to_str().unwrap(),
            "--state-dir",
            unrelated.to_str().unwrap(),
            "deprovision",
        ])
        .output()
        .unwrap();

    assert!(preview.status.success());
    assert!(!unrelated.join(".buzzr-state").exists());
    assert_eq!(
        std::fs::read_to_string(unrelated.join("keep.txt")).unwrap(),
        "user data\n"
    );
}

#[test]
fn deprovision_fails_closed_on_corrupt_provenance() {
    let fixture = fixture();
    std::fs::write(&fixture.store.path, "{not json\n").unwrap();

    let preview = Command::new(env!("CARGO_BIN_EXE_buzzr"))
        .args([
            "--config",
            fixture.config_path.to_str().unwrap(),
            "--state-dir",
            fixture.store.directory.to_str().unwrap(),
            "deprovision",
        ])
        .output()
        .unwrap();

    assert!(!preview.status.success());
    assert!(String::from_utf8_lossy(&preview.stderr).contains("cannot parse"));
    assert!(fixture.config_path.exists());
    assert!(!fixture.buzz_calls.exists());
    assert!(!fixture.docker_calls.exists());
}
