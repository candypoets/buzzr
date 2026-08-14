//! Failure-injection checks for crash-consistent destructive provenance.

#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

use buzzr::clients::NostrTools;
use buzzr::config::{BridgeConfig, Config};
use buzzr::state::StateStore;
use buzzr::sync::reconcile;
use buzzr::topology::{SpaceBinding, Topology};
use serde_json::json;

fn config_for(executable: &std::path::Path) -> Config {
    let private_key = "1".repeat(64);
    let public_key = NostrTools::new().public_key(&private_key).unwrap();
    Config {
        bridge: BridgeConfig {
            buzz_bin: executable.to_string_lossy().into_owned(),
            bridge_public_key: Some(public_key),
            sync_enabled: true,
            avatars_enabled: false,
            ..BridgeConfig::default()
        },
        identities: HashMap::new(),
        secrets: HashMap::from([("BUZZR_BRIDGE_PRIVATE_KEY".to_string(), private_key)]),
    }
}

fn one_space() -> Topology {
    Topology {
        spaces: vec![SpaceBinding {
            workspace_id: "w1".to_string(),
            workspace_label: "Alpha".to_string(),
            channel_name: "alpha".to_string(),
            number: 1,
            agents: Vec::new(),
        }],
        warnings: Vec::new(),
    }
}

#[test]
fn created_channel_is_checkpointed_before_a_later_membership_failure() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    std::fs::write(
        &executable,
        "#!/bin/sh\n\
         set -eu\n\
         case \"$1 $2\" in\n\
           \"channels list\") printf '%s\\n' '[]' ;;\n\
           \"channels create\") printf '%s\\n' \
             '{\"channel_id\":\"11111111-2222-3333-4444-555555555555\"}' ;;\n\
           \"channels update\") printf '%s\\n' '{}' ;;\n\
           \"channels members\") printf '%s\\n' '[]' ;;\n\
           \"channels add-member\") echo 'injected membership failure' >&2; exit 1 ;;\n\
           *) echo \"unexpected: $*\" >&2; exit 2 ;;\n\
         esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

    let config = config_for(&executable);
    let topology = one_space();
    let store = StateStore::new(directory.path().join("state"));

    let error = reconcile(&config, &topology, &store, true).unwrap_err();
    assert!(error.to_string().contains("injected membership failure"));
    let state = store.load_strict().unwrap();
    assert_eq!(state["channels"]["w1"]["origin"], json!("created"));
    assert_eq!(
        state["channels"]["w1"]["channel_id"],
        json!("11111111-2222-3333-4444-555555555555")
    );
    let bridge_pubkey = config.bridge.bridge_public_key.as_ref().unwrap();
    assert_eq!(
        state["managed_resources"]["channel_memberships"]["11111111-2222-3333-4444-555555555555"]
            [bridge_pubkey]["origin"],
        json!("adding")
    );
}

#[test]
fn interrupted_channel_creation_is_recovered_from_write_ahead_state() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    let remote_created = directory.path().join("remote-created");
    let bridge_pubkey = NostrTools::new().public_key(&"1".repeat(64)).unwrap();
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\n\
             set -eu\n\
             case \"$1 $2\" in\n\
               \"channels list\")\n\
                 if [ -f '{}' ]; then\n\
                   marker=$(cat '{}')\n\
                   printf '[{{\"channel_id\":\"11111111-2222-3333-4444-555555555555\",\"name\":\"alpha\",\"description\":\"[%s]\"}}]\\n' \"$marker\"\n\
                 else printf '%s\\n' '[]'; fi ;;\n\
               \"channels create\")\n\
                 description=''\n\
                 while [ \"$#\" -gt 0 ]; do\n\
                   if [ \"$1\" = '--description' ]; then description=\"$2\"; break; fi\n\
                   shift\n\
                 done\n\
                 printf '%s\\n' \"$description\" | sed -n 's/.*\\[\\(buzzr-create:[0-9a-f]*\\)\\].*/\\1/p' > '{}'\n\
                 echo 'response lost' >&2; exit 1 ;;\n\
               \"channels update\") printf '%s\\n' '{{}}' ;;\n\
               \"channels members\") printf '%s\\n' '[{{\"pubkey\":\"{}\",\"role\":\"owner\"}}]' ;;\n\
               \"channels add-member\") echo 'stop after recovery' >&2; exit 1 ;;\n\
               *) echo \"unexpected: $*\" >&2; exit 2 ;;\n\
             esac\n",
            remote_created.display(),
            remote_created.display(),
            remote_created.display(),
            bridge_pubkey,
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = config_for(&executable);
    config.bridge.human_pubkey = Some("c".repeat(64));
    let topology = one_space();
    let store = StateStore::new(directory.path().join("state"));

    let first = reconcile(&config, &topology, &store, true).unwrap_err();
    assert!(first.to_string().contains("response lost"));
    assert_eq!(
        store.load_strict().unwrap()["channels"]["w1"]["origin"],
        json!("creating")
    );

    let second = reconcile(&config, &topology, &store, true).unwrap_err();
    assert!(second.to_string().contains("stop after recovery"));
    let recovered = store.load_strict().unwrap();
    assert_eq!(recovered["channels"]["w1"]["origin"], json!("created"));
    assert_eq!(
        recovered["channels"]["w1"]["channel_id"],
        json!("11111111-2222-3333-4444-555555555555")
    );
}

#[test]
fn reappearing_space_unarchives_its_original_created_channel() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    let calls = directory.path().join("calls");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\n\
             set -eu\n\
             printf '%s\\n' \"$*\" >> '{}'\n\
             case \"$1 $2\" in\n\
               \"channels list\") printf '%s\\n' '[]' ;;\n\
               \"channels unarchive\") printf '%s\\n' '{{}}' ;;\n\
               \"channels members\") printf '%s\\n' '[]' ;;\n\
               \"channels add-member\") echo 'stop after unarchive' >&2; exit 1 ;;\n\
               *) echo \"unexpected: $*\" >&2; exit 2 ;;\n\
             esac\n",
            calls.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = config_for(&executable);
    let topology = one_space();
    let store = StateStore::new(directory.path().join("state"));
    let mut state = buzzr::state::default_state();
    state["channels"]["w1"] = json!({
        "channel_id": "11111111-2222-3333-4444-555555555555",
        "name": "alpha",
        "space_label": "Alpha",
        "origin": "created",
        "archived": true,
    });
    store.save(&state).unwrap();

    let error = reconcile(&config, &topology, &store, true).unwrap_err();
    assert!(error.to_string().contains("stop after unarchive"));
    let recovered = store.load_strict().unwrap();
    assert_eq!(recovered["channels"]["w1"]["origin"], json!("created"));
    assert_ne!(recovered["channels"]["w1"]["archived"], json!(true));
    let calls = std::fs::read_to_string(calls).unwrap();
    assert!(calls.contains("channels unarchive --channel 11111111-2222-3333-4444-555555555555"));
}
